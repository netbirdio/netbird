package networkmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protobuf "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestDecodePolicy(t *testing.T) {
	assert.Equal(t,
		nmdata.Resource{Type: "peer", ID: "valid-id"},
		resourceFromProto(
			&proto.ResourceCompact{Type: "peer", PeerIndexSet: true, PeerIndex: uint32(1)},
			[]string{"invalid-id-0", "valid-id", "invalid-id-2"}))
	// check invalid peer index returns an empty resource
	assert.Equal(t,
		nmdata.Resource{},
		resourceFromProto(
			&proto.ResourceCompact{Type: "peer", PeerIndexSet: true, PeerIndex: uint32(100)},
			[]string{"invalid-id-0", "valid-id", "invalid-id-2"}))
	assert.Equal(t,
		nmdata.Resource{Type: "domain", ID: "domain"},
		resourceFromProto(
			&proto.ResourceCompact{Type: "domain", Id: "domain"}, []string{}))
	assert.Equal(t,
		nmdata.Resource{Type: "host", ID: "host"},
		resourceFromProto(
			&proto.ResourceCompact{Type: "host", Id: "host"}, []string{}))
	assert.Equal(t,
		nmdata.Resource{Type: "subnet", ID: "subnet"},
		resourceFromProto(
			&proto.ResourceCompact{Type: "subnet", Id: "subnet"}, []string{}))
	// an unknown resource type return an empty resource
	assert.Equal(t,
		nmdata.Resource{},
		resourceFromProto(
			&proto.ResourceCompact{Type: "boom", Id: "boom"}, []string{}))
}

// ResourceCompact fields 1-3 are the v0.77 wire contract. Retyping any of them
// makes peers on either side of the change silently drop policy resources, so
// the encoding is pinned here as raw bytes: field 1 "peer" (bytes), field 2
// true (varint), field 3 7 (varint).
func TestResourceCompactLegacyWireFormat(t *testing.T) {
	legacy := []byte{0x0a, 0x04, 'p', 'e', 'e', 'r', 0x10, 0x01, 0x18, 0x07}

	var decoded proto.ResourceCompact
	require.NoError(t, protobuf.Unmarshal(legacy, &decoded))
	assert.Equal(t, "peer", decoded.Type)
	assert.True(t, decoded.PeerIndexSet)
	assert.Equal(t, uint32(7), decoded.PeerIndex)

	encoded, err := protobuf.Marshal(&proto.ResourceCompact{Type: "peer", PeerIndexSet: true, PeerIndex: 7})
	require.NoError(t, err)
	assert.Equal(t, legacy, encoded)
}
