package networkmap_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	goproto "google.golang.org/protobuf/proto"

	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	nbnetworkmap "github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// TestEnvelopeToNetworkMap_RoundTrip exercises the full client-side pipeline:
// build a small components struct, encode an envelope, marshal/unmarshal the
// wire bytes, decode back via EnvelopeToNetworkMap, and verify the result is
// non-empty and consistent.
func TestEnvelopeToNetworkMap_RoundTrip(t *testing.T) {
	c, localPeerKey := buildSmokeComponents(t)

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})

	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err, "marshal envelope")

	var decoded proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decoded), "unmarshal envelope")

	result, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), &decoded, localPeerKey, "netbird.cloud")
	require.NoError(t, err, "EnvelopeToNetworkMap")
	require.NotNil(t, result)
	require.NotNil(t, result.NetworkMap, "decoded NetworkMap must be non-nil")
	require.NotNil(t, result.Components, "Components must be retained for future delta updates")
	require.NotNil(t, result.Components.AccountSettings)
	require.NotEmpty(t, result.NetworkMap.RemotePeers, "two-peer allow policy should produce one remote peer")
	require.NotEmpty(t, result.NetworkMap.FirewallRules, "two-peer allow policy should produce firewall rules")
}

// TestCalculate_FirewallRuleProtocol_NeverNetbirdSSH guards against the
// scenario where a rule with Protocol=NetbirdSSH leaks the enum value into
// proto.FirewallRule.Protocol. Calculate() must rewrite NetbirdSSH → TCP
// before forming firewall rules. Without that rewrite, agents fall into
// UNKNOWN-protocol handling, which on some platforms downgrades to
// allow-all — a real security regression.
func TestCalculate_FirewallRuleProtocol_NeverNetbirdSSH(t *testing.T) {
	c, localPeerKey := buildSmokeComponents(t)
	// Replace the smoke policy with a NetbirdSSH-protocol allow.
	c.Policies = []*types.Policy{{
		ID: "pol-ssh", AccountSeqID: 2, Enabled: true,
		Rules: []*types.PolicyRule{{
			ID:            "rule-ssh",
			Enabled:       true,
			Action:        types.PolicyTrafficActionAccept,
			Protocol:      types.PolicyRuleProtocolNetbirdSSH,
			Bidirectional: true,
			Sources:       []string{"group-all"},
			Destinations:  []string{"group-all"},
		}},
	}}

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})
	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err)
	var decoded proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decoded))

	result, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), &decoded, localPeerKey, "netbird.cloud")
	require.NoError(t, err)
	require.NotEmpty(t, result.NetworkMap.FirewallRules, "ssh policy should produce firewall rules")
	for i, fr := range result.NetworkMap.FirewallRules {
		require.NotEqualf(t, proto.RuleProtocol_NETBIRD_SSH, fr.Protocol,
			"FirewallRules[%d].Protocol must be the rewritten TCP, not NETBIRD_SSH", i)
	}
}

func TestEnvelopeToNetworkMap_NilEnvelope(t *testing.T) {
	_, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), nil, "key", "netbird.cloud")
	require.Error(t, err, "nil envelope must produce an error rather than panic")
}

func TestEnvelopeToNetworkMap_FullPayloadMissing(t *testing.T) {
	env := &proto.NetworkMapEnvelope{}
	_, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), env, "key", "netbird.cloud")
	require.Error(t, err, "envelope with no Full payload must produce an error")
}

// TestDecodeEnvelope_MalformedWgKeyPeerSkipped feeds an envelope where one
// peer has a wg_pub_key that is not 32 bytes long. The decoder must skip
// that peer (keeping the rest of the snapshot usable) instead of aborting
// the whole sync — mirrors legacy behaviour that tolerates an occasional
// bad row.
func TestDecodeEnvelope_MalformedWgKeyPeerSkipped(t *testing.T) {
	c, localPeerKey := buildSmokeComponents(t)
	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})
	require.NotNil(t, envelope.GetFull())

	full := envelope.GetFull()
	require.Len(t, full.Peers, 2, "smoke fixture should have two peers")

	// Truncate the second peer's wg_pub_key so it fails the length gate.
	full.Peers[1].WgPubKey = full.Peers[1].WgPubKey[:31]

	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err, "marshal envelope")
	var decoded proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decoded), "unmarshal envelope")

	result, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), &decoded, localPeerKey, "netbird.cloud")
	require.NoError(t, err, "EnvelopeToNetworkMap must tolerate one bad peer key")
	require.NotNil(t, result)
	require.NotNil(t, result.Components)
	require.Len(t, result.Components.Peers, 1, "the well-formed peer survives, the malformed one is dropped")
}

// buildSmokeComponents returns a minimal NetworkMapComponents (2 peers, 1
// group, 1 allow policy) plus the receiving peer's WG public key. Sufficient
// to validate the encode → marshal → decode → Calculate pipeline produces
// non-empty output.
func buildSmokeComponents(t *testing.T) (*types.NetworkMapComponents, string) {
	t.Helper()

	peerAKey := randomWgKey(t)
	peerBKey := randomWgKey(t)

	peerA := &nbpeer.Peer{
		ID:       "peer-A",
		Key:      peerAKey,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 1}),
		DNSLabel: "peerA",
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
	}
	peerB := &nbpeer.Peer{
		ID:       "peer-B",
		Key:      peerBKey,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 2}),
		DNSLabel: "peerB",
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
	}

	group := &types.Group{
		ID: "group-all", AccountSeqID: 1, Name: "All",
		Peers: []string{"peer-A", "peer-B"},
	}

	policy := &types.Policy{
		ID: "pol-allow", AccountSeqID: 1, Enabled: true,
		Rules: []*types.PolicyRule{{
			ID:            "rule-allow",
			Enabled:       true,
			Action:        types.PolicyTrafficActionAccept,
			Protocol:      types.PolicyRuleProtocolALL,
			Bidirectional: true,
			Sources:       []string{"group-all"},
			Destinations:  []string{"group-all"},
		}},
	}

	c := &types.NetworkMapComponents{
		PeerID: "peer-A",
		Network: &types.Network{
			Identifier: "net-smoke",
			Net:        net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
			Serial:     1,
		},
		AccountSettings: &types.AccountSettingsInfo{},
		DNSSettings:     &types.DNSSettings{},
		Peers: map[string]*nbpeer.Peer{
			"peer-A": peerA,
			"peer-B": peerB,
		},
		Groups: map[string]*types.Group{
			"group-all": group,
		},
		Policies: []*types.Policy{policy},
	}
	return c, peerAKey
}

func randomWgKey(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	_, err := rand.Read(raw[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw[:])
}
