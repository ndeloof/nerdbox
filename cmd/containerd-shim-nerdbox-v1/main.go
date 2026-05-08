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

package main

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/containerd/containerd/v2/pkg/shim"

	"github.com/containerd/nerdbox/internal/diag"
	"github.com/containerd/nerdbox/internal/logging"
	"github.com/containerd/nerdbox/pkg/shim/manager"

	_ "github.com/containerd/nerdbox/plugins/shim/sandbox"
	_ "github.com/containerd/nerdbox/plugins/shim/streaming"
	_ "github.com/containerd/nerdbox/plugins/shim/task"
	_ "github.com/containerd/nerdbox/plugins/shim/transfer"
	_ "github.com/containerd/nerdbox/plugins/vm/libkrun"
)

func init() {
	logging.SetupShimLog()

	// Skip diag noise for the short-lived "start" / "delete" actions
	// that share this binary; they don't have a streaming surface and
	// the shim log isn't even opened for them (see logging.SetupShimLog).
	for _, a := range os.Args[1:] {
		if a == "start" || a == "delete" {
			return
		}
	}

	diag.LifecycleEvent("ShimMain.start", "", "",
		slog.Int("pid", os.Getpid()),
		slog.String("argv", strings.Join(os.Args, " ")),
	)
}

func main() {
	shim.RunShim(context.Background(), manager.New("io.containerd.nerdbox.v1"),
		func(c *shim.Config) {
			c.NoSetupLogger = true
		},
	)
	// shim.RunShim returns when the shim's main loop exits. Capture a
	// final goroutine snapshot so we can spot any leaked goroutines at
	// process exit time.
	diag.LifecycleEvent("ShimMain.exit", "", "")
	diag.DumpGoroutines("shim_main_exit")
}
