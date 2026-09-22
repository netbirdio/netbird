package types

import (
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// TestHandleVNCRule_BidirectionalDistributesPubkeyToSourcePeer covers the
// latent bug where a bidirectional VNC rule used to drop the
// SessionPubKey for the peer that appears only in sources, even though
// the rule explicitly grants access in both directions. Without the
// pubkey, the source peer's Noise_IK authorizer would not recognise the
// client's static key and Noise handshakes against it would fail. The
// fix in handleVNCRule must distribute the pubkey to either side of a
// bidirectional rule.
func TestHandleVNCRule_BidirectionalDistributesPubkeyToSourcePeer(t *testing.T) {
	rule := &nmdata.PolicyRule{
		Protocol:           string(PolicyRuleProtocolNetbirdVNC),
		Bidirectional:      true,
		AuthorizedUser:     "user1",
		SessionPubKey:      "pubkey-base64",
		SessionDisplayName: "Alice",
	}
	cb := RuleAuthCallbacks{
		CollectVNCUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {},
	}
	state := NewPeerConnResolveState()

	cb.handleVNCRule(rule, true /*peerInSources*/, false /*peerInDestinations*/, state)

	if len(state.VNCSessionPubKeys) != 1 {
		t.Fatalf("expected 1 session pubkey distributed to source peer of bidirectional rule, got %d", len(state.VNCSessionPubKeys))
	}
	if state.VNCSessionPubKeys[0].PubKey != "pubkey-base64" {
		t.Fatalf("unexpected pubkey: %q", state.VNCSessionPubKeys[0].PubKey)
	}
}

// TestHandleVNCRule_UnidirectionalSourceGetsNoPubkey makes sure the fix
// above didn't widen pubkey distribution past the bidirectional case:
// a strictly source-to-destination rule still must not push the
// SessionPubKey to peers that appear only in sources.
func TestHandleVNCRule_UnidirectionalSourceGetsNoPubkey(t *testing.T) {
	rule := &nmdata.PolicyRule{
		Protocol:       string(PolicyRuleProtocolNetbirdVNC),
		Bidirectional:  false,
		AuthorizedUser: "user1",
		SessionPubKey:  "pubkey-base64",
	}
	cb := RuleAuthCallbacks{
		CollectVNCUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {},
	}
	state := NewPeerConnResolveState()

	cb.handleVNCRule(rule, true /*peerInSources*/, false /*peerInDestinations*/, state)

	if len(state.VNCSessionPubKeys) != 0 {
		t.Fatalf("expected NO pubkey for source peer of unidirectional rule, got %d", len(state.VNCSessionPubKeys))
	}
}

// TestHandleVNCRule_DestinationAlwaysGetsPubkey is the baseline case:
// destination peers must always receive the SessionPubKey since they're
// the ones that need to authenticate the incoming Noise handshake.
func TestHandleVNCRule_DestinationAlwaysGetsPubkey(t *testing.T) {
	rule := &nmdata.PolicyRule{
		Protocol:       string(PolicyRuleProtocolNetbirdVNC),
		Bidirectional:  false,
		AuthorizedUser: "user1",
		SessionPubKey:  "pubkey-base64",
	}
	cb := RuleAuthCallbacks{
		CollectVNCUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {},
	}
	state := NewPeerConnResolveState()

	cb.handleVNCRule(rule, false /*peerInSources*/, true /*peerInDestinations*/, state)

	if len(state.VNCSessionPubKeys) != 1 {
		t.Fatalf("expected 1 session pubkey for destination peer, got %d", len(state.VNCSessionPubKeys))
	}
}

// TestApplyResolvedRule_SSHSkipsSourcePeer locks SSH authorization to the
// destination side. Unlike VNC, whose Noise_IK handshake needs the session
// pubkey on both ends of a bidirectional rule, SSH authorization follows the
// destination alone: a peer that appears only in a rule's sources must not get
// SSH enabled or authorized users collected, bidirectional or not.
func TestApplyResolvedRule_SSHSkipsSourcePeer(t *testing.T) {
	for _, bidirectional := range []bool{true, false} {
		t.Run(fmt.Sprintf("bidirectional=%t", bidirectional), func(t *testing.T) {
			collected := false
			cb := RuleAuthCallbacks{
				CollectSSHUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {
					collected = true
				},
			}
			rule := &nmdata.PolicyRule{
				Protocol:      string(PolicyRuleProtocolNetbirdSSH),
				Bidirectional: bidirectional,
			}
			state := NewPeerConnResolveState()

			ApplyResolvedRuleToState(rule, nil, nil, true /*peerInSources*/, false /*peerInDestinations*/, false, func(*nmdata.PolicyRule, []*nmdata.Peer, int) {}, cb, state)

			if state.SSHEnabled {
				t.Fatal("expected SSH NOT enabled on source-only peer of SSH rule")
			}
			if collected {
				t.Fatal("expected NO authorized users collected on source-only peer of SSH rule")
			}
		})
	}
}

// TestApplyResolvedRule_SSHEnablesDestinationPeer is the positive counterpart:
// a peer in the rule's destinations gets SSH enabled and its authorized users
// collected.
func TestApplyResolvedRule_SSHEnablesDestinationPeer(t *testing.T) {
	collected := false
	cb := RuleAuthCallbacks{
		CollectSSHUsers: func(_ *nmdata.PolicyRule, target map[string]map[string]struct{}) {
			collected = true
			target["local"] = map[string]struct{}{"user1": {}}
		},
	}
	rule := &nmdata.PolicyRule{
		Protocol:      string(PolicyRuleProtocolNetbirdSSH),
		Action:        string(PolicyTrafficActionAccept),
		Bidirectional: true,
	}
	state := NewPeerConnResolveState()

	ApplyResolvedRuleToState(rule, nil, nil, false /*peerInSources*/, true /*peerInDestinations*/, false, func(*nmdata.PolicyRule, []*nmdata.Peer, int) {}, cb, state)

	if !state.SSHEnabled {
		t.Fatal("expected SSH enabled on destination-side peer of SSH rule")
	}
	if !collected {
		t.Fatal("expected authorized users collected on destination-side peer of SSH rule")
	}
	if _, ok := state.AuthorizedUsers["local"]; !ok {
		t.Fatal("expected authorized users map populated for destination-side peer")
	}
}

// TestApplyResolvedRule_LegacySSHSkipsSourcePeer covers the same boundary for
// the legacy TCP/22 path, which enables SSH off the peer's own flag.
func TestApplyResolvedRule_LegacySSHSkipsSourcePeer(t *testing.T) {
	rule := &nmdata.PolicyRule{
		Protocol:      string(PolicyRuleProtocolTCP),
		Ports:         []string{"22"},
		Bidirectional: true,
	}
	cb := RuleAuthCallbacks{
		GetAllowedUserIDs: func() map[string]struct{} {
			return map[string]struct{}{"user1": {}}
		},
	}
	state := NewPeerConnResolveState()

	ApplyResolvedRuleToState(rule, nil, nil, true /*peerInSources*/, false /*peerInDestinations*/, true /*targetPeerSSHEnabled*/, func(*nmdata.PolicyRule, []*nmdata.Peer, int) {}, cb, state)

	if state.SSHEnabled {
		t.Fatal("expected SSH NOT enabled on source-only peer of legacy SSH rule")
	}
	if len(state.AuthorizedUsers) != 0 {
		t.Fatalf("expected no authorized users for source-only peer, got %v", state.AuthorizedUsers)
	}
}

// TestApplyResolvedRule_DropRuleGrantsNoAuthorization covers a rule written to
// deny: the firewall rule it emits carries the drop, but the authorization
// switch must not read it as a grant. Without this, a netbird-ssh rule with
// action=drop and no authorized groups falls to the default branch and hands
// the account's whole allowed-user set to the wildcard key.
func TestApplyResolvedRule_DropRuleGrantsNoAuthorization(t *testing.T) {
	for _, protocol := range []PolicyRuleProtocolType{
		PolicyRuleProtocolNetbirdSSH,
		PolicyRuleProtocolNetbirdVNC,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			collectedSSH, collectedVNC := false, false
			cb := RuleAuthCallbacks{
				CollectSSHUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {
					collectedSSH = true
				},
				CollectVNCUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {
					collectedVNC = true
				},
				GetAllowedUserIDs: func() map[string]struct{} {
					return map[string]struct{}{"user1": {}}
				},
			}
			rule := &nmdata.PolicyRule{
				Protocol:       string(protocol),
				Action:         string(PolicyTrafficActionDrop),
				SessionPubKey:  "pubkey",
				AuthorizedUser: "user1",
			}
			state := NewPeerConnResolveState()

			emitted := 0
			ApplyResolvedRuleToState(rule, nil, nil, false, true /*peerInDestinations*/, true,
				func(*nmdata.PolicyRule, []*nmdata.Peer, int) { emitted++ }, cb, state)

			if emitted == 0 {
				t.Fatal("expected the drop rule to still be emitted to the firewall")
			}
			if state.SSHEnabled {
				t.Fatal("expected SSH NOT enabled by a drop rule")
			}
			if collectedSSH || collectedVNC {
				t.Fatal("expected no authorized users collected from a drop rule")
			}
			if len(state.VNCSessionPubKeys) != 0 {
				t.Fatal("expected no VNC session pubkeys distributed by a drop rule")
			}
		})
	}
}

// TestApplyResolvedRule_UnknownActionGrantsNoAuthorization: an action this code
// does not recognise as an accept must not grant either.
func TestApplyResolvedRule_UnknownActionGrantsNoAuthorization(t *testing.T) {
	collected := false
	cb := RuleAuthCallbacks{
		CollectSSHUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {
			collected = true
		},
	}
	rule := &nmdata.PolicyRule{
		Protocol: string(PolicyRuleProtocolNetbirdSSH),
		Action:   "quarantine",
	}
	state := NewPeerConnResolveState()

	ApplyResolvedRuleToState(rule, nil, nil, false, true, false, func(*nmdata.PolicyRule, []*nmdata.Peer, int) {}, cb, state)

	if state.SSHEnabled || collected {
		t.Fatal("expected an unrecognized action to grant nothing")
	}
}

// TestNormalizePolicyRuleProtocol_PortlessMarkerRulesAreScoped: a marker-protocol
// rule with no ports of its own must be scoped to the port that protocol
// implies. A portless netbird-ssh rule otherwise generates a bare tcp firewall
// rule, which opens every TCP port on the destination.
func TestNormalizePolicyRuleProtocol_PortlessMarkerRulesAreScoped(t *testing.T) {
	cases := []struct {
		protocol  PolicyRuleProtocolType
		wantPorts []string
	}{
		{PolicyRuleProtocolNetbirdSSH, []string{"22022"}},
		{PolicyRuleProtocolNetbirdVNC, []string{strconv.Itoa(VNCInternalPort)}},
	}
	for _, tc := range cases {
		t.Run(string(tc.protocol), func(t *testing.T) {
			rule := &nmdata.PolicyRule{Protocol: string(tc.protocol)}
			effective, protocol := NormalizePolicyRuleProtocol(rule)

			if protocol != PolicyRuleProtocolTCP {
				t.Fatalf("expected wire protocol tcp, got %s", protocol)
			}
			if !slices.Equal(effective.Ports, tc.wantPorts) {
				t.Fatalf("expected ports %v, got %v", tc.wantPorts, effective.Ports)
			}
			if len(rule.Ports) != 0 {
				t.Fatal("expected the caller's rule to be left untouched")
			}
		})
	}
}

// A marker rule that declares its own ports keeps them, and a plain protocol is
// never given ports it did not ask for.
func TestNormalizePolicyRuleProtocol_LeavesOtherRulesAlone(t *testing.T) {
	explicit := &nmdata.PolicyRule{Protocol: string(PolicyRuleProtocolNetbirdSSH), Ports: []string{"2222"}}
	effective, _ := NormalizePolicyRuleProtocol(explicit)
	if effective != explicit {
		t.Fatal("expected a rule with its own ports to be returned as-is")
	}

	portless := &nmdata.PolicyRule{Protocol: string(PolicyRuleProtocolTCP)}
	effective, protocol := NormalizePolicyRuleProtocol(portless)
	if effective != portless || len(effective.Ports) != 0 {
		t.Fatal("expected a portless tcp rule to be left unscoped")
	}
	if protocol != PolicyRuleProtocolTCP {
		t.Fatalf("expected tcp, got %s", protocol)
	}
}
