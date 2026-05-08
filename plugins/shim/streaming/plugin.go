/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package streaming

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"

	streamapi "github.com/containerd/containerd/api/services/streaming/v1"
	ptypes "github.com/containerd/containerd/v2/pkg/protobuf/types"
	cplugins "github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/log"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
	"github.com/containerd/ttrpc"
	typeurl "github.com/containerd/typeurl/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/containerd/nerdbox/internal/diag"
	"github.com/containerd/nerdbox/internal/shim/sandbox"
	"github.com/containerd/nerdbox/plugins"
)

func init() {
	registry.Register(&plugin.Registration{
		Type: cplugins.TTRPCPlugin,
		ID:   "streaming",
		Requires: []plugin.Type{
			plugins.SandboxPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			sb, err := ic.GetSingle(plugins.SandboxPlugin)
			if err != nil {
				return nil, err
			}

			return &service{
				sb: sb.(sandbox.Sandbox),
			}, nil
		},
	})
}

// maxFrameSize is the maximum allowed frame payload (10 MiB).
const maxFrameSize = 10 << 20

type service struct {
	sb sandbox.Sandbox
}

func (s *service) RegisterTTRPC(server *ttrpc.Server) error {
	streamapi.RegisterTTRPCStreamingService(server, s)
	return nil
}

func (s *service) Stream(ctx context.Context, srv streamapi.TTRPCStreaming_StreamServer) error {
	diag.StreamEvent("handler_enter", "")
	// Receive the StreamInit message with the stream ID
	a, err := srv.Recv()
	if err != nil {
		diag.StreamEvent("init_recv_err", "", slog.Any("err", err))
		return err
	}
	var i streamapi.StreamInit
	if err := typeurl.UnmarshalTo(a, &i); err != nil {
		diag.StreamEvent("init_unmarshal_err", "", slog.Any("err", err))
		return err
	}

	diag.StreamEvent("init_received", i.ID)
	log.G(ctx).WithField("stream", i.ID).Debug("creating stream bridge")

	// Create a stream connection to the VM, passing through the stream ID
	vmConn, err := s.sb.StartStream(ctx, i.ID)
	if err != nil {
		diag.StreamEvent("start_stream_err", i.ID, slog.Any("err", err))
		return fmt.Errorf("failed to start vm stream: %w", err)
	}
	defer func() {
		diag.StreamEvent("vm_conn_close_deferred", i.ID)
		if cerr := vmConn.Close(); cerr != nil {
			diag.VMConnClosed(i.ID, cerr)
		}
	}()

	diag.StreamEvent("bridge_established", i.ID)
	log.G(ctx).WithField("stream", i.ID).Debug("stream bridge established")

	// Send ack back to containerd client
	e, _ := typeurl.MarshalAnyToProto(&ptypes.Empty{})
	if err := srv.Send(e); err != nil {
		diag.StreamEvent("ack_send_err", i.ID, slog.Any("err", err))
		return err
	}
	diag.StreamEvent("ack_sent", i.ID)

	// Bridge messages in both directions as length-prefixed proto frames.

	// Client -> server: forward incoming messages to the VM.
	go func() {
		diag.StreamEvent("c2s_bridge_start", i.ID)
		err := bridgeTTRPCToVM(srv, vmConn)
		diag.StreamEvent("c2s_bridge_return", i.ID, slog.Any("err", err))
		// Signal end-of-stream to the VM with a zero-length frame.
		// We avoid CloseWrite() because the vsock proxy turns a
		// transport-level shutdown into a bidirectional SHUTDOWN,
		// which would kill the reverse direction and can cause the
		// peer to lose in-flight data.
		//
		// Log the EOF marker failure independently: when the bridge
		// returns io.EOF (client CloseSend) the dropped marker would
		// otherwise be lost both by the err==nil check and the
		// io.EOF filter on the bridge log below, leaving the VM
		// hanging while waiting for the marker.
		if eofErr := binary.Write(vmConn, binary.BigEndian, uint32(0)); eofErr != nil {
			diag.StreamEvent("c2s_eof_marker_err", i.ID, slog.Any("err", eofErr))
			log.G(ctx).WithError(eofErr).WithField("stream", i.ID).Debug("failed to write EOF marker to vm")
		} else {
			diag.StreamEvent("c2s_eof_marker_sent", i.ID)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			log.G(ctx).WithError(err).WithField("stream", i.ID).Debug("client->server bridge ended")
		}
	}()

	// Server -> client: forward VM messages back to the caller.
	v2t := make(chan error, 1)
	go func() {
		diag.StreamEvent("s2c_bridge_start", i.ID)
		err := bridgeVMToTTRPC(vmConn, srv)
		diag.StreamEvent("s2c_bridge_return", i.ID, slog.Any("err", err))
		v2t <- err
	}()

	// The protocol contract is that the server initiates the close:
	// once it has finished its work it writes a zero-length frame,
	// which bridgeVMToTTRPC observes and returns nil for. Returning
	// before that signal would race the deferred vmConn.Close()
	// against the server's in-flight reads/writes and could silently
	// drop data still buffered in the kernel.
	//
	// We deliberately do not also wait on the client->server
	// direction: it can stay blocked in srv.Recv() if the client only
	// issues CloseSend after observing the server's EOF, which itself
	// requires this handler to return so ttrpc closes the server
	// stream. Waiting would deadlock. Instead the goroutine exits on
	// its own when ttrpc cancels the stream context on handler
	// return (or when vmConn.Close unblocks an in-flight write).
	select {
	case err := <-v2t:
		diag.StreamEvent("select_v2t", i.ID, slog.Any("err", err))
		if err != nil && !errors.Is(err, io.EOF) {
			log.G(ctx).WithError(err).WithField("stream", i.ID).Debug("server->client bridge ended")
			// Unexpected vsock/ttrpc termination — capture stacks.
			diag.VMConnClosed(i.ID, err)
		}
	case <-ctx.Done():
		diag.StreamEvent("select_ctx_done", i.ID, slog.Any("err", ctx.Err()))
		// ctx cancelled before the server-side EOF: this is the
		// "wsarecv: forcibly closed" signature in Mode 1.
		diag.TTRPCClosed("shim_streaming", ctx.Err())
	}

	diag.StreamEvent("handler_exit", i.ID)
	return nil
}

// bridgeTTRPCToVM reads typeurl.Any messages from the TTRPC stream and
// writes them as length-prefixed proto frames to the VM connection.
func bridgeTTRPCToVM(srv streamapi.TTRPCStreaming_StreamServer, conn io.Writer) error {
	for {
		a, err := srv.Recv()
		if err != nil {
			return err
		}

		data, err := proto.Marshal(typeurl.MarshalProto(a))
		if err != nil {
			return fmt.Errorf("failed to marshal for vm: %w", err)
		}
		if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
			return fmt.Errorf("failed to write frame length to vm: %w", err)
		}
		if _, err := conn.Write(data); err != nil {
			return fmt.Errorf("failed to write frame data to vm: %w", err)
		}
	}
}

// bridgeVMToTTRPC reads length-prefixed proto frames from the VM
// connection and sends them as typeurl.Any messages on the TTRPC stream.
func bridgeVMToTTRPC(conn io.Reader, srv streamapi.TTRPCStreaming_StreamServer) error {
	for {
		var length uint32
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return err
		}
		// A zero-length frame is an application-level EOF marker.
		if length == 0 {
			return nil
		}
		if length > maxFrameSize {
			return fmt.Errorf("frame size %d exceeds maximum %d", length, maxFrameSize)
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(conn, data); err != nil {
			return fmt.Errorf("failed to read frame data from vm: %w", err)
		}
		var a anypb.Any
		if err := proto.Unmarshal(data, &a); err != nil {
			return fmt.Errorf("failed to unmarshal from vm: %w", err)
		}
		if err := srv.Send(&a); err != nil {
			return err
		}
	}
}
