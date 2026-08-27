package types

import (
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

// TestApplyResolvedRule_BidirectionalSSHEnablesSourcePeer locks the
// bidirectional widening for netbird-ssh rules: a peer that appears only
// in the rule's sources of a bidirectional SSH rule must get SSH enabled
// and its authorized users collected, because the rule grants access in
// both directions. A unidirectional rule must not do this for a
// source-only peer.
func TestApplyResolvedRule_BidirectionalSSHEnablesSourcePeer(t *testing.T) {
	collected := false
	cb := RuleAuthCallbacks{
		CollectSSHUsers: func(_ *nmdata.PolicyRule, target map[string]map[string]struct{}) {
			collected = true
			target["local"] = map[string]struct{}{"user1": {}}
		},
	}
	rule := &nmdata.PolicyRule{
		Protocol:      string(PolicyRuleProtocolNetbirdSSH),
		Bidirectional: true,
	}
	state := NewPeerConnResolveState()

	ApplyResolvedRuleToState(rule, nil, nil, true /*peerInSources*/, false /*peerInDestinations*/, false, func(*nmdata.PolicyRule, []*nmdata.Peer, int) {}, cb, state)

	if !state.SSHEnabled {
		t.Fatal("expected SSH enabled on source-side peer of bidirectional SSH rule")
	}
	if !collected {
		t.Fatal("expected authorized users collected on source-side peer of bidirectional SSH rule")
	}
	if _, ok := state.AuthorizedUsers["local"]; !ok {
		t.Fatal("expected authorized users map populated for source-side peer")
	}
}

// TestApplyResolvedRule_UnidirectionalSSHSkipsSourcePeer is the negative
// counterpart: a unidirectional SSH rule must not enable SSH for a peer
// that appears only in sources.
func TestApplyResolvedRule_UnidirectionalSSHSkipsSourcePeer(t *testing.T) {
	collected := false
	cb := RuleAuthCallbacks{
		CollectSSHUsers: func(_ *nmdata.PolicyRule, _ map[string]map[string]struct{}) {
			collected = true
		},
	}
	rule := &nmdata.PolicyRule{
		Protocol:      string(PolicyRuleProtocolNetbirdSSH),
		Bidirectional: false,
	}
	state := NewPeerConnResolveState()

	ApplyResolvedRuleToState(rule, nil, nil, true /*peerInSources*/, false /*peerInDestinations*/, false, func(*nmdata.PolicyRule, []*nmdata.Peer, int) {}, cb, state)

	if state.SSHEnabled {
		t.Fatal("expected SSH NOT enabled on source-only peer of unidirectional SSH rule")
	}
	if collected {
		t.Fatal("expected NO authorized users collected on source-only peer of unidirectional SSH rule")
	}
}
