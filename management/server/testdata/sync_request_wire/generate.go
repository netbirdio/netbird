//go:build ignore

// generate.go produces the frozen SyncRequest wire-format fixtures used by
// server_sync_legacy_wire_test.go. Run with:
//
//	go run ./management/server/testdata/sync_request_wire/generate.go
//
// Each fixture is the proto-serialised SyncRequest a client of the indicated
// netbird version would put on the wire. protobuf3 is forward-compatible: an
// old client's fields live at stable tag numbers, so marshalling a current
// SyncRequest that sets only those fields produces bytes byte-for-byte
// compatible with what the old client produced. The fixtures are checked in
// so a future proto change that silently breaks the old wire format is caught
// in CI.
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
		// v0.20.0: message SyncRequest {} — no fields on the wire.
		"v0_20_0.bin": {},

		// v0.40.0: Meta added at tag 1. Older meta fields only.
		"v0_40_0.bin": {
			Meta: &mgmtProto.PeerSystemMeta{
				Hostname:       "v40-host",
				GoOS:           "linux",
				OS:             "linux",
				Platform:       "x86_64",
				Kernel:         "4.15.0",
				NetbirdVersion: "0.40.0",
			},
		},

		// v0.60.0: same wire shape as v0.40.0 for SyncRequest.
		"v0_60_0.bin": {
			Meta: &mgmtProto.PeerSystemMeta{
				Hostname:       "v60-host",
				GoOS:           "linux",
				OS:             "linux",
				Platform:       "x86_64",
				Kernel:         "5.15.0",
				NetbirdVersion: "0.60.0",
			},
		},

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
