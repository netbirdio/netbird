package types

import "testing"

// TestHandleVNCRule_BidirectionalDistributesPubkeyToSourcePeer covers the
// latent bug where a bidirectional VNC rule used to drop the
// SessionPubKey for the peer that appears only in sources, even though
// the rule explicitly grants access in both directions. Without the
// pubkey, the source peer's Noise_IK authorizer would not recognise the
// client's static key and Noise handshakes against it would fail. The
// fix in handleVNCRule must distribute the pubkey to either side of a
// bidirectional rule.
func TestHandleVNCRule_BidirectionalDistributesPubkeyToSourcePeer(t *testing.T) {
	rule := &PolicyRule{
		Protocol:           PolicyRuleProtocolNetbirdVNC,
		Bidirectional:      true,
		AuthorizedUser:     "user1",
		SessionPubKey:      "pubkey-base64",
		SessionDisplayName: "Alice",
	}
	cb := ruleAuthCallbacks{
		collectVNCUsers: func(_ *PolicyRule, _ map[string]map[string]struct{}) {},
	}
	state := &peerConnResolveState{
		vncAuthorizedUsers: make(map[string]map[string]struct{}),
	}

	cb.handleVNCRule(rule, true /*peerInSources*/, false /*peerInDestinations*/, state)

	if len(state.vncSessionPubKeys) != 1 {
		t.Fatalf("expected 1 session pubkey distributed to source peer of bidirectional rule, got %d", len(state.vncSessionPubKeys))
	}
	if state.vncSessionPubKeys[0].PubKey != "pubkey-base64" {
		t.Fatalf("unexpected pubkey: %q", state.vncSessionPubKeys[0].PubKey)
	}
}

// TestHandleVNCRule_UnidirectionalSourceGetsNoPubkey makes sure the fix
// above didn't widen pubkey distribution past the bidirectional case:
// a strictly source-to-destination rule still must not push the
// SessionPubKey to peers that appear only in sources.
func TestHandleVNCRule_UnidirectionalSourceGetsNoPubkey(t *testing.T) {
	rule := &PolicyRule{
		Protocol:       PolicyRuleProtocolNetbirdVNC,
		Bidirectional:  false,
		AuthorizedUser: "user1",
		SessionPubKey:  "pubkey-base64",
	}
	cb := ruleAuthCallbacks{
		collectVNCUsers: func(_ *PolicyRule, _ map[string]map[string]struct{}) {},
	}
	state := &peerConnResolveState{
		vncAuthorizedUsers: make(map[string]map[string]struct{}),
	}

	cb.handleVNCRule(rule, true /*peerInSources*/, false /*peerInDestinations*/, state)

	if len(state.vncSessionPubKeys) != 0 {
		t.Fatalf("expected NO pubkey for source peer of unidirectional rule, got %d", len(state.vncSessionPubKeys))
	}
}

// TestHandleVNCRule_DestinationAlwaysGetsPubkey is the baseline case:
// destination peers must always receive the SessionPubKey since they're
// the ones that need to authenticate the incoming Noise handshake.
func TestHandleVNCRule_DestinationAlwaysGetsPubkey(t *testing.T) {
	rule := &PolicyRule{
		Protocol:       PolicyRuleProtocolNetbirdVNC,
		Bidirectional:  false,
		AuthorizedUser: "user1",
		SessionPubKey:  "pubkey-base64",
	}
	cb := ruleAuthCallbacks{
		collectVNCUsers: func(_ *PolicyRule, _ map[string]map[string]struct{}) {},
	}
	state := &peerConnResolveState{
		vncAuthorizedUsers: make(map[string]map[string]struct{}),
	}

	cb.handleVNCRule(rule, false /*peerInSources*/, true /*peerInDestinations*/, state)

	if len(state.vncSessionPubKeys) != 1 {
		t.Fatalf("expected 1 session pubkey for destination peer, got %d", len(state.vncSessionPubKeys))
	}
}
