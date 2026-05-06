package peer

import (
	"os"
	"strings"
	"testing"
)

// Regression test for the lazy-mode routed-subnet wake-up bug.
//
// Background: when a NetBird peer is also a routing peer (advertises
// subnets like 192.168.91.0/24 via NetBird Networks), the route-manager
// appends those subnets as AllowedIPs to the WG peer entry. When the
// lazy-connection-manager deactivates the peer (relay-inactivity
// timeout, WG-handshake-timeout-recover), the current code path calls
// peer.Conn.Close() which unconditionally calls
// endpointUpdater.RemoveWgPeer() -- which removes the ENTIRE WG peer
// entry, including the routed-subnet AllowedIPs.
//
// The lazy-listener then re-arms the peer with ONLY the basic peer-IP
// /32 AllowedIPs. The route-manager's allowedIPsRefCounter is unaware
// of the round-trip and does not re-apply the routed subnets. Until the
// next traffic to the peer's NetBird IP wakes the peer (and the
// route-manager's reconcile re-runs), routed-subnet traffic to those
// prefixes is silently dropped by WG.
//
// The fix introduces a `keepWgPeer bool` parameter on Close(). Lazy-
// suspend callers pass true (don't remove the WG peer entry, just
// suspend the data path); permanent-removal callers pass false
// (preserve the original behaviour for engine.removePeer / mode-change
// tear-down).
//
// This test is a static-text check: it asserts the Conn.Close signature
// exposes the keepWgPeer parameter AND that RemoveWgPeer is gated on
// it. A heavier behavioural test would need a stub WgInterface plus
// route-manager plumbing; this version catches accidental signature
// reverts cheaply and points at the exact landmark if the invariant is
// broken.
//
// Tracked in docs/bugs/2026-05-04-lazy-wake-on-routed-subnet.md.
func TestConn_Close_KeepWgPeerParameterPresent(t *testing.T) {
	src, err := os.ReadFile("conn.go")
	if err != nil {
		t.Fatalf("read conn.go: %v", err)
	}
	body := string(src)

	// Signature landmark: Close must accept the keepWgPeer argument.
	const sig = "func (conn *Conn) Close(signalToRemote bool, keepWgPeer bool)"
	if !strings.Contains(body, sig) {
		t.Errorf("Conn.Close signature missing keepWgPeer parameter — the lazy-suspend path will remove the WG peer and drop routed-subnet AllowedIPs (see docs/bugs/2026-05-04-lazy-wake-on-routed-subnet.md). Expected: %q", sig)
	}

	// Gate landmark: RemoveWgPeer must be guarded by !keepWgPeer.
	closeBody := extractFunctionBody(t, body, "Close")
	const guarded = "if !keepWgPeer"
	if !strings.Contains(closeBody, guarded) {
		t.Errorf("Conn.Close body missing %q guard around endpointUpdater.RemoveWgPeer — without it, routed-subnet AllowedIPs are dropped on every lazy-suspend cycle", guarded)
	}
	const removeCall = "endpointUpdater.RemoveWgPeer()"
	if !strings.Contains(closeBody, removeCall) {
		t.Errorf("Conn.Close body missing %q call — the permanent-removal path still needs to remove the WG peer (only the lazy-suspend path keeps it)", removeCall)
	}

	// The guard must appear BEFORE the call, otherwise RemoveWgPeer
	// would always run.
	guardIdx := strings.Index(closeBody, guarded)
	callIdx := strings.Index(closeBody, removeCall)
	if guardIdx < 0 || callIdx < 0 {
		return // already reported above
	}
	if guardIdx > callIdx {
		t.Errorf("guard %q (idx %d) must come BEFORE %q (idx %d)", guarded, guardIdx, removeCall, callIdx)
	}
}

// All call sites of Conn.Close in conn_mgr.go must pass an explicit
// keepWgPeer value chosen for the call's intent. The four documented
// call sites:
//
//   * RelayInactiveChan handler           -> keepWgPeer=true  (lazy suspend)
//   * RecoverPeerToIdle (WG-timeout)      -> keepWgPeer=true  (lazy suspend, Phase 3.7i)
//   * RemovePeerConn                      -> keepWgPeer=false (permanent removal)
//   * mode-change tear-down (resetPeers)  -> keepWgPeer=false (full reopen)
//
// This test asserts no zero-arg or 1-arg Close call survives in
// conn_mgr.go after the fix.
func TestConnMgr_AllCloseCallersPassKeepWgPeer(t *testing.T) {
	src, err := os.ReadFile("../conn_mgr.go")
	if err != nil {
		t.Fatalf("read conn_mgr.go: %v", err)
	}
	body := string(src)

	// Crude but effective: scan every line for ".Close(" on a peer.Conn
	// receiver and confirm it has TWO arguments separated by a comma.
	// Lines that match the legacy 1-arg form (e.g. ".Close(false)") are
	// flagged.
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if !strings.Contains(line, ".Close(") {
			continue
		}
		// Filter to only peer-Conn-style closes (skip Logger.Close, etc).
		// The peer-Conn form is "<varname>.Close(...)" where varname is
		// usually "conn" / "peerConn" — exclude obvious non-peer Closes.
		trim := strings.TrimSpace(line)
		switch {
		case strings.Contains(trim, "lazyConnMgr.Close"),
			strings.Contains(trim, "activityManager.Close"),
			strings.Contains(trim, "im.Close"),
			strings.Contains(trim, "peerStore.Close"),
			strings.Contains(trim, "// "),
			!(strings.Contains(trim, "conn.Close(") || strings.Contains(trim, "peerConn.Close(")):
			continue
		}
		// Now check the arg count.
		open := strings.Index(line, ".Close(")
		if open < 0 {
			continue
		}
		args := line[open+len(".Close("):]
		closeIdx := strings.Index(args, ")")
		if closeIdx < 0 {
			continue // multi-line call, give up
		}
		argList := strings.TrimSpace(args[:closeIdx])
		if !strings.Contains(argList, ",") {
			t.Errorf("conn_mgr.go:%d: peer.Conn.Close call missing keepWgPeer second argument: %q", i+1, trim)
		}
	}
}
