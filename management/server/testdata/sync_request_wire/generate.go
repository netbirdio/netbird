//go:build ignore

// generate.go produces the SyncRequest wire-format fixtures that the current
// netbird client (and the android variant) put on the wire. These two files
// are regenerated at CI time — run with:
//
//	go run ./management/server/testdata/sync_request_wire/generate.go
//
// The legacy fixtures (v0_20_0.bin, v0_40_0.bin, v0_60_0.bin) are frozen
// snapshots of what older clients sent. They are checked in and intentionally
// never regenerated here, so a future proto change that silently breaks the
// old wire format is caught by CI replaying the frozen bytes.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang/protobuf/proto" //nolint:staticcheck // wire-format stability

	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

func main() {
	outDir := filepath.Join("management", "server", "testdata", "sync_request_wire")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	fixtures := map[string]*mgmtProto.SyncRequest{
		// current: fully-populated meta a modern client would send.
		"current.bin": {
			Meta: &mgmtProto.PeerSystemMeta{
				Hostname:       "modern-host",
				GoOS:           "linux",
				OS:             "linux",
				Platform:       "x86_64",
				Kernel:         "6.5.0",
				NetbirdVersion: "0.70.0",
				UiVersion:      "0.70.0",
				KernelVersion:  "6.5.0-rc1",
			},
		},

		// android: exercises the never-skip branch regardless of cache state.
		"android_current.bin": {
			Meta: &mgmtProto.PeerSystemMeta{
				Hostname:       "android-host",
				GoOS:           "android",
				OS:             "android",
				Platform:       "arm64",
				Kernel:         "4.19",
				NetbirdVersion: "0.70.0",
			},
		},
	}

	for name, msg := range fixtures {
		payload, err := proto.Marshal(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal %s: %v\n", name, err)
			os.Exit(1)
		}
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, len(payload))
	}
}
