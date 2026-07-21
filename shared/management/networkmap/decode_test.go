package networkmap

import (
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/types"
	"github.com/stretchr/testify/assert"
)

func TestDecodePolicy(t *testing.T) {
	assert.Equal(t,
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_peer, ResourceId: &proto.ResourceCompact_PeerIndex{PeerIndex: uint32(1)}},
			[]string{"invalid-id-0", "valid-id", "invalid-id-2"}),
		types.Resource{Type: "peer", ID: "valid-id"})
	// check invalid peer index returns an empty resource
	assert.Equal(t,
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_peer, ResourceId: &proto.ResourceCompact_PeerIndex{PeerIndex: uint32(100)}},
			[]string{"invalid-id-0", "valid-id", "invalid-id-2"}),
		types.Resource{})
	assert.Equal(t,
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_domain, ResourceId: &proto.ResourceCompact_Id{Id: "domain"}}, []string{}),
		types.Resource{Type: "domain", ID: "domain"})
	assert.Equal(t,
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_host, ResourceId: &proto.ResourceCompact_Id{Id: "host"}}, []string{}),
		types.Resource{Type: "host", ID: "host"})
	assert.Equal(t,
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_subnet, ResourceId: &proto.ResourceCompact_Id{Id: "subnet"}}, []string{}),
		types.Resource{Type: "subnet", ID: "subnet"})
	// an unknown resource type return an empty resource
	assert.Equal(t,
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_unknown_type, ResourceId: &proto.ResourceCompact_Id{Id: "boom"}}, []string{}),
		types.Resource{})
}
