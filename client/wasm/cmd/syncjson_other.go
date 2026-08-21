//go:build js && !tinygo

package main

import (
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

// marshalSyncJSON renders a SyncResponse to JSON for the JS bridge. Non-TinyGo
// builds use the stock protojson runtime (full reflection).
func marshalSyncJSON(m *mgmProto.SyncResponse) ([]byte, error) {
	return protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		AllowPartial:    true,
	}.Marshal(m)
}
