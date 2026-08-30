package networkmap_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	goproto "google.golang.org/protobuf/proto"

	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/types"
	nbnetworkmap "github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
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
	c.Policies = []*nmdata.Policy{{
		ID: "pol-ssh", PublicID: "2", Enabled: true,
		Rules: []*nmdata.PolicyRule{{
			ID:            "rule-ssh",
			Enabled:       true,
			Action:        string(types.PolicyTrafficActionAccept),
			Protocol:      string(types.PolicyRuleProtocolNetbirdSSH),
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
	for _, p := range full.Peers {
		if base64.StdEncoding.EncodeToString(p.WgPubKey) != localPeerKey {
			p.WgPubKey = p.WgPubKey[:31]
		}
	}

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

// TestEnvelopeRoundTrip_AllGroupShortCircuitParity reproduces prod accounts
// with several groups literally named "All" where the "All"-named group does
// not contain every peer. Server-side Calculate short-circuits destination
// expansion at the first group named "All" (getUniquePeerIDsFromGroupsIDs),
// ignoring the remaining destination groups. The wire must preserve enough
// group identity for the decoded components to short-circuit identically —
// otherwise the client unions all destination groups and emits extra
// firewall rules the server never produced.
func TestEnvelopeRoundTrip_AllGroupShortCircuitParity(t *testing.T) {
	ctx := context.Background()

	peers := map[string]*nmdata.Peer{}
	for i, id := range []string{"peer-T", "peer-S", "peer-ALL", "peer-O"} {
		peers[id] = &nmdata.Peer{
			ID:       id,
			Key:      randomWgKey(t),
			IP:       netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)}),
			DNSLabel: id,
			Meta:     nmdata.PeerSystemMeta{WtVersion: "0.40.0"},
		}
	}

	c := &types.NetworkMapComponents{
		PeerID: "peer-T",
		Network: &nmdata.Network{
			Identifier: "net-all-groups",
			Net:        net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
			Serial:     1,
		},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
		Peers:           peers,
		Groups: map[string]*nmdata.Group{
			"g-src": {PublicID: "1", Name: "staff", Peers: []string{"peer-T", "peer-S"}},
			"g-all": {PublicID: "2", Name: "All", Peers: []string{"peer-ALL"}},
			"g-two": {PublicID: "3", Name: "second", Peers: []string{"peer-T", "peer-O"}},
		},
		Policies: []*nmdata.Policy{{
			ID: "pol-multi-dest", PublicID: "10", Enabled: true,
			Rules: []*nmdata.PolicyRule{{
				ID:           "rule-multi-dest",
				Enabled:      true,
				Action:       string(types.PolicyTrafficActionAccept),
				Protocol:     string(types.PolicyRuleProtocolALL),
				Sources:      []string{"g-src"},
				Destinations: []string{"g-all", "g-two"},
			}},
		}},
	}

	serverNM := c.Calculate(ctx)
	require.NotNil(t, serverNM)

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})
	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err, "marshal envelope")
	var decodedEnv proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decodedEnv), "unmarshal envelope")

	result, err := nbnetworkmap.EnvelopeToNetworkMap(ctx, &decodedEnv, peers["peer-T"].Key, "netbird.cloud")
	require.NoError(t, err, "EnvelopeToNetworkMap")
	clientNM := result.NetworkMap

	serverRules := make([]string, 0, len(serverNM.FirewallRules))
	for _, r := range serverNM.FirewallRules {
		serverRules = append(serverRules, fmt.Sprintf("%s/%d", r.PeerIP, r.Direction))
	}
	clientRules := make([]string, 0, len(clientNM.FirewallRules))
	for _, r := range clientNM.FirewallRules {
		clientRules = append(clientRules, fmt.Sprintf("%s/%d", r.PeerIP, r.Direction)) // nolint:staticcheck
	}
	require.ElementsMatch(t, serverRules, clientRules,
		"client-side Calculate must expand destination groups exactly like the server")

	serverPeers := make([]string, 0, len(serverNM.Peers))
	for _, p := range serverNM.Peers {
		serverPeers = append(serverPeers, p.Key)
	}
	clientPeers := make([]string, 0, len(clientNM.RemotePeers))
	for _, p := range clientNM.RemotePeers {
		clientPeers = append(clientPeers, p.WgPubKey)
	}
	require.ElementsMatch(t, serverPeers, clientPeers,
		"client-side Calculate must connect the same remote peers as the server")
}

// TestEnvelopeToNetworkMap_EmptyComponents covers the graceful-degrade path
// the server takes for a peer that is missing from the account or absent from
// the validated-peers map. The legacy server short-circuited before
// Calculate() and shipped a NetworkMap carrying only the account Network; the
// components path runs Calculate() on the client instead, so the envelope must
// carry Network or the client panics dereferencing a nil *types.Network.
func TestEnvelopeToNetworkMap_EmptyComponents(t *testing.T) {
	localPeerKey := randomWgKey(t)
	c := types.EmptyNetworkMapComponents(&types.NetworkMapComponents{
		PeerID: "peer-A",
		Network: &nmdata.Network{
			Identifier: "net-empty",
			Net:        net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
			Serial:     7,
		},
		Peers: map[string]*nmdata.Peer{
			"peer-A": {ID: "peer-A", Key: localPeerKey, IP: netip.AddrFrom4([4]byte{100, 64, 0, 1})},
		},
	})

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})
	require.NotNil(t, envelope.GetFull().Network, "empty envelope must carry the account Network")

	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err, "marshal envelope")
	var decoded proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decoded), "unmarshal envelope")

	result, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), &decoded, localPeerKey, "netbird.cloud")
	require.NoError(t, err, "EnvelopeToNetworkMap must degrade gracefully on empty components")
	require.Equal(t, uint64(7), result.NetworkMap.Serial)
	require.Empty(t, result.NetworkMap.RemotePeers, "unvalidated peer connects to nobody")
}

// TestEnvelopeToNetworkMap_MissingNetwork simulates a server that omits
// AccountNetwork from the envelope. Clients must degrade rather than panic, so
// they survive talking to a management server that predates the encoder fix.
func TestEnvelopeToNetworkMap_MissingNetwork(t *testing.T) {
	c, localPeerKey := buildSmokeComponents(t)

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})
	envelope.GetFull().Network = nil

	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err, "marshal envelope")
	var decoded proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decoded), "unmarshal envelope")

	result, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), &decoded, localPeerKey, "netbird.cloud")
	require.NoError(t, err, "a missing AccountNetwork must not panic the client")
	require.NotNil(t, result.Components.Network)
	require.NotEmpty(t, result.NetworkMap.RemotePeers, "the rest of the snapshot stays usable")
}

// buildSmokeComponents returns a minimal NetworkMapComponents (2 peers, 1
// group, 1 allow policy) plus the receiving peer's WG public key. Sufficient
// to validate the encode → marshal → decode → Calculate pipeline produces
// non-empty output.
func buildSmokeComponents(t *testing.T) (*types.NetworkMapComponents, string) {
	t.Helper()

	peerAKey := randomWgKey(t)
	peerBKey := randomWgKey(t)

	peerA := &nmdata.Peer{
		ID:       "peer-A",
		Key:      peerAKey,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 1}),
		DNSLabel: "peerA",
		Meta:     nmdata.PeerSystemMeta{WtVersion: "0.40.0"},
	}
	peerB := &nmdata.Peer{
		ID:       "peer-B",
		Key:      peerBKey,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 2}),
		DNSLabel: "peerB",
		Meta:     nmdata.PeerSystemMeta{WtVersion: "0.40.0"},
	}

	group := &nmdata.Group{
		PublicID: "1", Name: "All",
		Peers: []string{"peer-A", "peer-B"},
	}

	policy := &nmdata.Policy{
		ID: "pol-allow", PublicID: "1", Enabled: true,
		Rules: []*nmdata.PolicyRule{{
			ID:            "rule-allow",
			Enabled:       true,
			Action:        string(types.PolicyTrafficActionAccept),
			Protocol:      string(types.PolicyRuleProtocolALL),
			Bidirectional: true,
			Sources:       []string{"group-all"},
			Destinations:  []string{"group-all"},
		}},
	}

	c := &types.NetworkMapComponents{
		PeerID: "peer-A",
		Network: &nmdata.Network{
			Identifier: "net-smoke",
			Net:        net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
			Serial:     1,
		},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
		Peers: map[string]*nmdata.Peer{
			"peer-A": peerA,
			"peer-B": peerB,
		},
		Groups: map[string]*nmdata.Group{
			"group-all": group,
		},
		Policies: []*nmdata.Policy{policy},
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
