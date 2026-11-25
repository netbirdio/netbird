package networkmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protobuf "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/types"
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

// A management newer than this client can ship a protocol value this build has
// no case for. Mapping it to ALL would both widen the rule to every IP protocol
// and, because an ALL match short-circuits the port comparison, discard the
// port restriction the rule was written with. The rule must be dropped instead.
func TestDecodePolicyCompact_UnknownProtocolIsDropped(t *testing.T) {
	const futureProtocol = proto.RuleProtocol(99)

	pc := &proto.PolicyCompact{
		Id:       "policy-1",
		Action:   proto.RuleAction_ACCEPT,
		Protocol: futureProtocol,
		PortRanges: []*proto.PortInfo_Range{
			{Start: 25900, End: 25900},
		},
		SourceGroupIds:      []string{"g-src"},
		DestinationGroupIds: []string{"g-dst"},
	}

	assert.Nil(t, decodePolicyCompact(pc, pc.Id, nil),
		"a rule with an unrecognized protocol must not decode into an enforceable rule")

	_, ok := protocolFromProto(futureProtocol)
	assert.False(t, ok, "an unrecognized protocol must not resolve to a known one")
}

// Every protocol the encoder can emit must survive a round trip, so the
// drop-on-unknown rule above cannot quietly start discarding valid policies.
func TestProtocolFromProto_KnownValuesRoundTrip(t *testing.T) {
	known := []proto.RuleProtocol{
		proto.RuleProtocol_ALL,
		proto.RuleProtocol_TCP,
		proto.RuleProtocol_UDP,
		proto.RuleProtocol_ICMP,
		proto.RuleProtocol_NETBIRD_SSH,
		proto.RuleProtocol_NETBIRD_VNC,
	}
	for _, p := range known {
		decoded, ok := protocolFromProto(p)
		require.Truef(t, ok, "protocol %s must decode", p)
		assert.Equalf(t, p, GetProtoProtocol(string(decoded)), "protocol %s must round trip", p)
	}
}

// An action the switch does not recognize must deny, not accept.
func TestActionFromProto_UnknownDenies(t *testing.T) {
	assert.Equal(t, types.PolicyTrafficActionAccept, actionFromProto(proto.RuleAction_ACCEPT))
	assert.Equal(t, types.PolicyTrafficActionDrop, actionFromProto(proto.RuleAction_DROP))
	assert.Equal(t, types.PolicyTrafficActionDrop, actionFromProto(proto.RuleAction(99)))
}
