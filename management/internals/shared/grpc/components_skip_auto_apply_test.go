package grpc

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	skipTestClientID = "peer-client"
	skipTestDNS      = "netbird.cloud"
)

// skipAutoApplyData is an account with one client allowed to reach two subnet resources
// behind one routing peer. The "manual" resource sets skip auto apply, "auto" does not.
func skipAutoApplyData() *networkmap.NetworkMapData {
	client := &nmdata.Peer{ID: skipTestClientID, Key: testWgKeyA, IP: netip.MustParseAddr("100.64.0.1"), DNSLabel: "client"}
	router := &nmdata.Peer{ID: "peer-router", Key: testWgKeyB, IP: netip.MustParseAddr("100.64.0.2"), DNSLabel: "router"}

	policy := &nmdata.Policy{
		ID: "pol-1", PublicID: "10", Enabled: true,
		Rules: []*nmdata.PolicyRule{{
			ID: "rule-1", PolicyID: "pol-1", Enabled: true,
			Action:       string(types.PolicyTrafficActionAccept),
			Protocol:     string(types.PolicyRuleProtocolALL),
			Sources:      []string{"group-clients"},
			Destinations: []string{"group-resources"},
		}},
	}

	return &networkmap.NetworkMapData{
		Peers: map[string]*nmdata.Peer{client.ID: client, router.ID: router},
		Groups: map[string]*nmdata.Group{
			"group-clients":   {ID: "group-clients", PublicID: "1", Name: "clients", Peers: []string{client.ID}},
			"group-resources": {ID: "group-resources", PublicID: "2", Name: "resources"},
		},
		ValidatedPeers:  map[string]struct{}{client.ID: {}, router.ID: {}},
		Network:         &nmdata.Network{Identifier: "network-1", Serial: 1},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
		Policies:        []*nmdata.Policy{policy},
		NetworkResources: []*nmdata.NetworkResource{
			{ID: "res-auto", PublicID: "20", NetworkID: "net-1", Name: "auto", Type: "subnet",
				Prefix: netip.MustParsePrefix("10.0.0.0/16"), Enabled: true},
			{ID: "res-manual", PublicID: "21", NetworkID: "net-1", Name: "manual", Type: "subnet",
				Prefix: netip.MustParsePrefix("10.1.0.0/16"), Enabled: true, SkipAutoApply: true},
		},
		ResourcePolicies: map[string][]*nmdata.Policy{"res-auto": {policy}, "res-manual": {policy}},
		Routers: map[string]map[string]*nmdata.NetworkRouter{
			"net-1": {router.ID: {PublicID: "30", Metric: 100, Enabled: true}},
		},
		NetworkXIDToPublicID: map[string]string{"net-1": "5"},
	}
}

// encodedEnvelope returns the wire bytes management sends a components client.
func encodedEnvelope(t *testing.T, nmd *networkmap.NetworkMapData) []byte {
	t.Helper()
	components := nmd.GetPeerNetworkMapComponents(skipTestClientID, nmdata.CustomZone{})
	require.NotNil(t, components)
	b, err := goproto.Marshal(EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: components}))
	require.NoError(t, err)
	return b
}

// clientRoutes runs the current client pipeline on envelope bytes and returns the
// skip auto apply value of each route by its network ID.
func clientRoutes(t *testing.T, wire []byte) map[string]bool {
	t.Helper()
	env := &proto.NetworkMapEnvelope{}
	require.NoError(t, goproto.Unmarshal(wire, env))
	res, err := networkmap.EnvelopeToNetworkMap(context.Background(), env, testWgKeyA, skipTestDNS, false)
	require.NoError(t, err)
	return routesByNetID(res.NetworkMap.GetRoutes())
}

func routesByNetID(routes []*proto.Route) map[string]bool {
	out := make(map[string]bool, len(routes))
	for _, r := range routes {
		out[r.GetNetID()] = r.GetSkipAutoApply()
	}
	return out
}

// schemaWithoutSkipAutoApply returns the envelope message type as it was before
// NetworkResourceRaw had skip_auto_apply, which is the schema older binaries carry.
func schemaWithoutSkipAutoApply(t *testing.T) protoreflect.MessageType {
	t.Helper()
	fdp := protodesc.ToFileDescriptorProto(proto.File_management_proto)
	removed := false
	for _, msg := range fdp.MessageType {
		if msg.GetName() != "NetworkResourceRaw" {
			continue
		}
		fields := msg.Field[:0]
		for _, f := range msg.Field {
			if f.GetName() == "skip_auto_apply" {
				removed = true
				continue
			}
			fields = append(fields, f)
		}
		msg.Field = fields
	}
	require.True(t, removed, "NetworkResourceRaw must have skip_auto_apply to strip")

	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	require.NoError(t, err)
	return dynamicpb.NewMessageType(fd.Messages().ByName("NetworkMapEnvelope"))
}

// throughOldSchema parses wire bytes with the old schema, dropping fields it does not
// know, and marshals them again. The result is what a binary built from the old schema
// understands, or sends.
func throughOldSchema(t *testing.T, oldType protoreflect.MessageType, wire []byte) []byte {
	t.Helper()
	msg := oldType.New().Interface()
	require.NoError(t, goproto.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(wire, msg),
		"the old schema must parse what new management sends")
	out, err := goproto.MarshalOptions{Deterministic: true}.Marshal(msg)
	require.NoError(t, err)
	return out
}

// TestNetworkResourceSkipAutoApply covers skip auto apply on network resources for every
// pairing of management and client versions. Each path ends in the proto routes the
// client route manager reads.
func TestNetworkResourceSkipAutoApply(t *testing.T) {
	t.Run("new management, new components client", func(t *testing.T) {
		routes := clientRoutes(t, encodedEnvelope(t, skipAutoApplyData()))

		require.Contains(t, routes, "auto", "the client must get a route for the auto applied resource")
		require.Contains(t, routes, "manual", "the client must get a route for the skip auto apply resource")
		assert.False(t, routes["auto"], "a resource without the flag is applied automatically")
		assert.True(t, routes["manual"], "the flag set on the resource must reach the client route")
	})

	t.Run("new management, older components client", func(t *testing.T) {
		// An older client parses the envelope with a schema that has no skip_auto_apply on
		// the resource. It must still parse it and route both resources, applied
		// automatically as before.
		wire := encodedEnvelope(t, skipAutoApplyData())
		routes := clientRoutes(t, throughOldSchema(t, schemaWithoutSkipAutoApply(t), wire))

		require.Contains(t, routes, "auto", "an older client must still get the auto applied resource")
		require.Contains(t, routes, "manual", "an older client must still get the skip auto apply resource")
		assert.False(t, routes["auto"], "an older client applies the resource automatically")
		assert.False(t, routes["manual"], "an older client does not see the flag and applies the resource automatically")
	})

	t.Run("older management, new components client", func(t *testing.T) {
		// Older management never sends the field. Its envelope is the same as one where no
		// resource sets the flag, so the new client applies every resource automatically.
		nmd := skipAutoApplyData()
		for _, r := range nmd.NetworkResources {
			r.SkipAutoApply = false
		}
		wire := encodedEnvelope(t, nmd)
		oldWire := throughOldSchema(t, schemaWithoutSkipAutoApply(t), wire)
		newWire, err := goproto.MarshalOptions{Deterministic: true}.Marshal(mustUnmarshalEnvelope(t, wire))
		require.NoError(t, err)
		assert.Equal(t, oldWire, newWire, "an envelope without the flag must be the bytes older management sends")

		routes := clientRoutes(t, oldWire)
		require.Contains(t, routes, "auto")
		require.Contains(t, routes, "manual")
		assert.False(t, routes["auto"], "without the field the resource is applied automatically")
		assert.False(t, routes["manual"], "without the field the resource is applied automatically")
	})

	t.Run("new management, client without components support", func(t *testing.T) {
		// Clients that do not advertise the components capability get routes management
		// computed, in NetworkMap.Routes. Route.skipAutoApply is older than the components
		// format, so these clients follow the flag once management sets it.
		nmd := skipAutoApplyData()
		components := nmd.GetPeerNetworkMapComponents(skipTestClientID, nmdata.CustomZone{})
		require.NotNil(t, components)
		nm := types.CalculateNetworkMapFromComponents(context.Background(), components)
		routes := routesByNetID(networkmap.ToProtocolRoutes(nm.Routes))

		require.Contains(t, routes, "auto")
		require.Contains(t, routes, "manual")
		assert.False(t, routes["auto"], "a resource without the flag is applied automatically")
		assert.True(t, routes["manual"], "the flag must reach the routes management computes")
	})
}

func mustUnmarshalEnvelope(t *testing.T, wire []byte) *proto.NetworkMapEnvelope {
	t.Helper()
	env := &proto.NetworkMapEnvelope{}
	require.NoError(t, goproto.Unmarshal(wire, env))
	return env
}
