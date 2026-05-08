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

// Package diag provides diagnostic helpers used by the instrumented shim
// build (branch diag/instrumented-shim-mode1) to capture goroutine dumps
// and structured lifecycle/stream timestamps when investigating ttrpc
// "wsarecv: forcibly closed" / vmConn close races (Mode 1 in sandboxes
// CI investigation).
//
// All helpers are additive and side-effect free in the absence of
// triggering events: they only emit structured logs at lifecycle/stream
// boundaries and dump goroutines on close-path errors. They do not
// alter any control flow.
package diag

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// LifecyclePrefix tags shim lifecycle handler entry/exit events so
	// they can be grep'd from the captured shim log: `[DIAG-LIFECYCLE]`.
	LifecyclePrefix = "[DIAG-LIFECYCLE]"

	// StreamPrefix tags streaming-plugin events: `[DIAG-STREAM]`.
	StreamPrefix = "[DIAG-STREAM]"

	// GoroutineDumpPrefix tags the goroutine dump emitted on stderr in
	// addition to the on-disk file: `=== NERDBOX-DIAG GOROUTINE DUMP ===`.
	GoroutineDumpPrefix = "=== NERDBOX-DIAG GOROUTINE DUMP ==="
)

// dumpThrottle limits how often we write a goroutine-dump file. The
// close paths we hook can fire repeatedly (one per stream + ttrpc
// listener), and a hot loop of dumps would obscure the timeline we are
// trying to capture. Successive triggers within this window are
// coalesced into a single dump.
const dumpThrottle = 250 * time.Millisecond

var (
	lastDumpUnixNano atomic.Int64
	dumpSeq          atomic.Uint64
	dumpDirOnce      sync.Once
	dumpDir          string
)

// nowMicros returns the current UTC time formatted with microsecond
// precision and a trailing 'Z'. Used for both filenames and log lines.
func nowMicros() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
}

// resolveDumpDir picks the directory where goroutine dumps are
// written. Order:
//  1. NERDBOX_DIAG_DIR env (if set and writable),
//  2. %TEMP% (Windows) / $TMPDIR (Unix),
//  3. os.TempDir() fallback.
func resolveDumpDir() string {
	dumpDirOnce.Do(func() {
		candidates := []string{
			os.Getenv("NERDBOX_DIAG_DIR"),
			os.Getenv("TEMP"),
			os.Getenv("TMPDIR"),
			os.TempDir(),
		}
		for _, c := range candidates {
			if c == "" {
				continue
			}
			if fi, err := os.Stat(c); err == nil && fi.IsDir() {
				dumpDir = c
				return
			}
		}
		dumpDir = "."
	})
	return dumpDir
}

// DumpGoroutines writes the full goroutine stack of the current process
// to a file named
// `nerdbox-shim-stack-<pid>-<UTC-iso8601>-<trigger>-<seq>.txt` under
// the resolved dump directory, and also writes a summary to stderr
// prefixed by [GoroutineDumpPrefix].
//
// Calls within [dumpThrottle] of the previous successful dump are
// coalesced (only the trigger label is emitted to stderr). Returns
// the file path written, or "" if no file was written this call.
func DumpGoroutines(trigger string) string {
	now := time.Now().UnixNano()
	last := lastDumpUnixNano.Load()
	if last != 0 && time.Duration(now-last) < dumpThrottle {
		fmt.Fprintf(os.Stderr, "%s coalesced trigger=%q (within %s of previous)\n",
			GoroutineDumpPrefix, trigger, dumpThrottle)
		return ""
	}
	if !lastDumpUnixNano.CompareAndSwap(last, now) {
		// Lost the race; another caller is dumping right now.
		return ""
	}

	seq := dumpSeq.Add(1)
	pid := os.Getpid()
	ts := nowMicros()
	// Sanitize trigger for filenames.
	safeTrigger := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			return r
		}
		return '_'
	}, trigger)

	name := fmt.Sprintf("nerdbox-shim-stack-%d-%s-%s-%d.txt",
		pid, strings.ReplaceAll(ts, ":", "-"), safeTrigger, seq)
	path := filepath.Join(resolveDumpDir(), name)

	// Grow buffer until runtime.Stack returns less than the buffer size.
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		if len(buf) >= 64<<20 {
			// 64 MiB ceiling — extreme case, accept truncation.
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}

	header := fmt.Sprintf(
		"# nerdbox shim goroutine dump\n"+
			"# pid=%d\n"+
			"# trigger=%s\n"+
			"# timestamp_utc=%s\n"+
			"# seq=%d\n"+
			"# goroutines=%d\n"+
			"# go_version=%s\n"+
			"# os/arch=%s/%s\n"+
			"\n",
		pid, trigger, ts, seq, runtime.NumGoroutine(),
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
	)

	if err := os.WriteFile(path, append([]byte(header), buf...), 0600); err != nil {
		fmt.Fprintf(os.Stderr,
			"%s failed to write %s: %v\n", GoroutineDumpPrefix, path, err)
		return ""
	}

	fmt.Fprintf(os.Stderr,
		"%s pid=%d trigger=%q ts=%s file=%s goroutines=%d\n",
		GoroutineDumpPrefix, pid, trigger, ts, path, runtime.NumGoroutine())

	// Also emit through slog so it lands in the shim's structured log
	// alongside lifecycle/stream events for easier correlation.
	slog.Warn("nerdbox diag goroutine dump",
		slog.String("event", "goroutine_dump"),
		slog.Int("pid", pid),
		slog.String("trigger", trigger),
		slog.String("ts_utc", ts),
		slog.String("file", path),
		slog.Int("goroutines", runtime.NumGoroutine()),
		slog.Uint64("seq", seq),
	)
	return path
}

// LifecycleEvent emits a `[DIAG-LIFECYCLE]` log line with microsecond
// UTC timestamp, phase name, container/exec ID and arbitrary structured
// fields. Pairs of (phase + ".enter", phase + ".exit") are intended to
// bracket each handler.
func LifecycleEvent(phase, containerID, execID string, fields ...slog.Attr) {
	attrs := make([]any, 0, 4+len(fields))
	attrs = append(attrs,
		slog.String("event", "lifecycle"),
		slog.String("ts_utc", nowMicros()),
		slog.String("phase", phase),
	)
	if containerID != "" {
		attrs = append(attrs, slog.String("container_id", containerID))
	}
	if execID != "" {
		attrs = append(attrs, slog.String("exec_id", execID))
	}
	for _, a := range fields {
		attrs = append(attrs, a)
	}
	slog.Info(LifecyclePrefix+" "+phase, attrs...)
}

// StreamEvent emits a `[DIAG-STREAM]` log line with microsecond UTC
// timestamp, event kind (e.g. "open", "ack", "vm_conn_close",
// "ctx_done", "bridge_end"), stream ID, and arbitrary structured
// fields.
func StreamEvent(kind, streamID string, fields ...slog.Attr) {
	attrs := make([]any, 0, 4+len(fields))
	attrs = append(attrs,
		slog.String("event", "stream"),
		slog.String("ts_utc", nowMicros()),
		slog.String("kind", kind),
	)
	if streamID != "" {
		attrs = append(attrs, slog.String("stream_id", streamID))
	}
	for _, a := range fields {
		attrs = append(attrs, a)
	}
	slog.Info(StreamPrefix+" "+kind, attrs...)
}

// VMConnClosed records a vmConn-side close event and triggers a
// goroutine dump. Used by the streaming plugin and any other site that
// owns the lifetime of a [net.Conn] to the VM.
func VMConnClosed(streamID string, cause error) {
	StreamEvent("vm_conn_close", streamID,
		slog.Any("cause", cause),
	)
	DumpGoroutines("vm_conn_close:" + streamID)
}

// TTRPCClosed records that a ttrpc transport observed a close /
// unexpected EOF and triggers a goroutine dump. The component label
// distinguishes shim-side (containerd<->shim) from VM-side
// (shim<->vminitd) events.
func TTRPCClosed(component string, cause error) {
	slog.Warn(GoroutineDumpPrefix+" ttrpc closed",
		slog.String("event", "ttrpc_closed"),
		slog.String("ts_utc", nowMicros()),
		slog.String("component", component),
		slog.Any("cause", cause),
	)
	DumpGoroutines("ttrpc_closed:" + component)
}
