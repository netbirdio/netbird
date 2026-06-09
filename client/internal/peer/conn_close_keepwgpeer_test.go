package peer

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestConn_Close_KeepWgPeerSignature pins the second parameter of
// (*Conn).Close so that the lazy-suspend caller chain (peerstore.PeerConn{Idle,Close}
// and engine race-loser cleanup) cannot be silently reverted to the
// single-bool form. Reflection is used so that the check survives any
// future renaming of the parameter as long as the type stays bool.
//
// The underlying bug, if the second parameter is dropped: when a routing
// peer is also a lazy-managed peer, Conn.Close calls
// endpointUpdater.RemoveWgPeer unconditionally, removing the WG peer
// entry and discarding all AllowedIPs the route-manager has appended
// in-place via WgInterface.AddAllowedIP. The next lazy-wake reopens the
// peer using only its original PeerConfig AllowedIPs (the peer-IP /32),
// so traffic to the advertised subnets is silently dropped by WG until
// the next mgmt-side reconcile re-applies the prefixes.
func TestConn_Close_KeepWgPeerSignature(t *testing.T) {
	m, ok := reflect.TypeOf((*Conn)(nil)).MethodByName("Close")
	if !ok {
		t.Fatal("(*Conn).Close not found")
	}

	// Method values include the receiver as the first input.
	const wantIn = 3 // receiver, signalToRemote bool, keepWgPeer bool
	if got := m.Type.NumIn(); got != wantIn {
		t.Fatalf("(*Conn).Close expected %d parameters (receiver + signalToRemote + keepWgPeer); got %d", wantIn, got)
	}

	boolType := reflect.TypeOf(true)
	for i := 1; i < wantIn; i++ {
		if got := m.Type.In(i); got != boolType {
			t.Errorf("(*Conn).Close parameter %d: want bool, got %s", i, got)
		}
	}
}

// TestConn_Close_KeepWgPeerGate confirms the body of Close routes the
// RemoveWgPeer call through the keepWgPeer guard. Reflection cannot see
// inside a method body, so this is a textual landmark test against
// conn.go. It is intentionally permissive about formatting (either an
// `if keepWgPeer { ... } else` or an `if !keepWgPeer { ... }` shape is
// accepted) but strict about the two invariants:
//
//  1. The keepWgPeer identifier appears in the same source area as the
//     RemoveWgPeer call (within ~25 lines).
//  2. RemoveWgPeer is still reachable for the keepWgPeer=false path —
//     i.e. the call has not been deleted outright.
//
// If either invariant fails, the lazy-suspend AllowedIPs preservation
// is at risk.
func TestConn_Close_KeepWgPeerGate(t *testing.T) {
	src, err := os.ReadFile("conn.go")
	if err != nil {
		t.Fatalf("read conn.go: %v", err)
	}
	body := string(src)

	const removeCall = "endpointUpdater.RemoveWgPeer()"
	idx := strings.Index(body, removeCall)
	if idx < 0 {
		t.Fatalf("conn.go no longer contains %q — the permanent-removal path is missing or has moved", removeCall)
	}

	// Look for the keepWgPeer identifier in a 25-line window above the
	// RemoveWgPeer call. 25 lines comfortably brackets the if/else shape
	// in the current implementation without becoming a whole-file scan.
	const window = 25
	start := idx
	for i, lines := idx, 0; i > 0 && lines < window; i-- {
		if body[i] == '\n' {
			lines++
			start = i
		}
	}
	if !strings.Contains(body[start:idx], "keepWgPeer") {
		t.Errorf("conn.go: %q is no longer gated by keepWgPeer within %d lines — every Close call would remove the WG peer entry, dropping route-manager-applied AllowedIPs on lazy-suspend", removeCall, window)
	}
}
