package networkmap

import (
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/assert"
)

func TestDecodePolicy(t *testing.T) {
	assert.Equal(t,
		nmdata.Resource{Type: "peer", ID: "valid-id"},
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_peer, ResourceId: &proto.ResourceCompact_PeerIndex{PeerIndex: uint32(1)}},
			[]string{"invalid-id-0", "valid-id", "invalid-id-2"}))
	// check invalid peer index returns an empty resource
	assert.Equal(t,
		nmdata.Resource{},
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_peer, ResourceId: &proto.ResourceCompact_PeerIndex{PeerIndex: uint32(100)}},
			[]string{"invalid-id-0", "valid-id", "invalid-id-2"}))
	assert.Equal(t,
		nmdata.Resource{Type: "domain", ID: "domain"},
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_domain, ResourceId: &proto.ResourceCompact_Id{Id: "domain"}}, []string{}))
	assert.Equal(t,
		nmdata.Resource{Type: "host", ID: "host"},
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_host, ResourceId: &proto.ResourceCompact_Id{Id: "host"}}, []string{}))
	assert.Equal(t,
		nmdata.Resource{Type: "subnet", ID: "subnet"},
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_subnet, ResourceId: &proto.ResourceCompact_Id{Id: "subnet"}}, []string{}))
	// an unknown resource type return an empty resource
	assert.Equal(t,
		nmdata.Resource{},
		resourceFromProto(
			&proto.ResourceCompact{Type: proto.ResourceCompactType_unknown_type, ResourceId: &proto.ResourceCompact_Id{Id: "boom"}}, []string{}))
}
