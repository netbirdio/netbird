//go:build js && tinygo

package main

import (
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// marshalSyncJSON renders a SyncResponse to JSON for the JS bridge. Under TinyGo
// the stock protojson runtime hits the reflect wall, so this uses the
// reflection-free AppendJSON emitted by embedpb (protojson-compatible:
// UseProtoNames + EmitUnpopulated).
func marshalSyncJSON(m *mgmProto.SyncResponse) ([]byte, error) {
	return m.AppendJSON(nil)
}
