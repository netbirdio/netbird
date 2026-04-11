package server

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestPendingStore_AddAndQuery(t *testing.T) {
	store := NewPendingStore(DefaultSessionTTL)

	peerIP := netip.MustParseAddr("100.64.0.1")
	session, err := store.Add(peerIP, "admin", ".", "user@example.com", "nonce-1")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if session.SessionID == "" {
		t.Fatal("expected non-empty session ID")
	}
	if session.PeerIP != peerIP {
		t.Errorf("expected peer IP %s, got %s", peerIP, session.PeerIP)
	}
	if session.OSUsername != "admin" {
		t.Errorf("expected username admin, got %s", session.OSUsername)
	}

	// Query should find the session
	found, ok := store.QueryByPeerIP(peerIP)
	if !ok {
		t.Fatal("expected to find pending session")
	}
	if found.SessionID != session.SessionID {
		t.Errorf("expected session %s, got %s", session.SessionID, found.SessionID)
	}

	// Query for different IP should not find anything
	_, ok = store.QueryByPeerIP(netip.MustParseAddr("100.64.0.2"))
	if ok {
		t.Fatal("expected no session for different IP")
	}
}

func TestPendingStore_Consume(t *testing.T) {
	store := NewPendingStore(DefaultSessionTTL)

	peerIP := netip.MustParseAddr("100.64.0.1")
	session, err := store.Add(peerIP, "admin", ".", "user@example.com", "nonce-2")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// First consume should succeed
	if !store.Consume(session.SessionID) {
		t.Fatal("expected first consume to succeed")
	}

	// Second consume should fail (already consumed)
	if store.Consume(session.SessionID) {
		t.Fatal("expected second consume to fail")
	}

	// Query should no longer find consumed session
	_, ok := store.QueryByPeerIP(peerIP)
	if ok {
		t.Fatal("expected consumed session to not be found by query")
	}
}

func TestPendingStore_Expiry(t *testing.T) {
	store := NewPendingStore(50 * time.Millisecond)

	peerIP := netip.MustParseAddr("100.64.0.1")
	session, err := store.Add(peerIP, "admin", ".", "user@example.com", "nonce-3")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Should be found immediately
	_, ok := store.QueryByPeerIP(peerIP)
	if !ok {
		t.Fatal("expected to find session before expiry")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should not be found after expiry
	_, ok = store.QueryByPeerIP(peerIP)
	if ok {
		t.Fatal("expected session to be expired")
	}

	// Consume should also fail
	if store.Consume(session.SessionID) {
		t.Fatal("expected consume of expired session to fail")
	}
}

func TestPendingStore_ReplayProtection(t *testing.T) {
	store := NewPendingStore(DefaultSessionTTL)

	peerIP := netip.MustParseAddr("100.64.0.1")
	_, err := store.Add(peerIP, "admin", ".", "user@example.com", "nonce-same")
	if err != nil {
		t.Fatalf("first Add failed: %v", err)
	}

	// Same nonce should be rejected
	_, err = store.Add(peerIP, "admin", ".", "user@example.com", "nonce-same")
	if err == nil {
		t.Fatal("expected duplicate nonce to be rejected")
	}
}

func TestPendingStore_Cleanup(t *testing.T) {
	store := NewPendingStore(50 * time.Millisecond)

	peerIP := netip.MustParseAddr("100.64.0.1")
	_, err := store.Add(peerIP, "admin", ".", "user@example.com", "nonce-cleanup")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if store.Count() != 1 {
		t.Fatalf("expected count 1, got %d", store.Count())
	}

	// Wait for expiry then trigger cleanup
	time.Sleep(100 * time.Millisecond)
	store.cleanup()

	if store.Count() != 0 {
		t.Fatalf("expected count 0 after cleanup, got %d", store.Count())
	}
}

func TestPendingStore_CleanupBackground(t *testing.T) {
	store := NewPendingStore(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store.StartCleanup(ctx)

	peerIP := netip.MustParseAddr("100.64.0.1")
	_, err := store.Add(peerIP, "admin", ".", "user@example.com", "nonce-bg-cleanup")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Wait for expiry + cleanup interval
	time.Sleep(200 * time.Millisecond)

	_, ok := store.QueryByPeerIP(peerIP)
	if ok {
		t.Fatal("expected session to be cleaned up")
	}
}

func TestPendingStore_ConcurrentAccess(t *testing.T) {
	store := NewPendingStore(DefaultSessionTTL)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ip := netip.AddrFrom4([4]byte{100, 64, byte(i / 256), byte(i % 256)})
			nonce := "nonce-" + string(rune(i+'A'))
			if i >= 26 {
				nonce = "nonce-" + string(rune(i-26+'a'))
			}

			session, err := store.Add(ip, "admin", ".", "user", nonce)
			if err != nil {
				return // nonce collision in test is expected
			}

			store.QueryByPeerIP(ip)
			store.Consume(session.SessionID)
		}(i)
	}

	wg.Wait()
}

func TestPendingStore_MultipleSessions(t *testing.T) {
	store := NewPendingStore(DefaultSessionTTL)

	ip1 := netip.MustParseAddr("100.64.0.1")
	ip2 := netip.MustParseAddr("100.64.0.2")

	s1, err := store.Add(ip1, "admin", ".", "user1", "nonce-a")
	if err != nil {
		t.Fatalf("Add s1 failed: %v", err)
	}

	s2, err := store.Add(ip2, "jdoe", "DOMAIN", "user2", "nonce-b")
	if err != nil {
		t.Fatalf("Add s2 failed: %v", err)
	}

	// Query each
	found1, ok := store.QueryByPeerIP(ip1)
	if !ok || found1.SessionID != s1.SessionID {
		t.Fatal("expected to find s1")
	}

	found2, ok := store.QueryByPeerIP(ip2)
	if !ok || found2.SessionID != s2.SessionID {
		t.Fatal("expected to find s2")
	}

	if found2.Domain != "DOMAIN" {
		t.Errorf("expected domain DOMAIN, got %s", found2.Domain)
	}

	if store.Count() != 2 {
		t.Errorf("expected count 2, got %d", store.Count())
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}

	nonce2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}

	if len(nonce1) != nonceLength*2 { // hex encoding doubles the length
		t.Errorf("expected nonce length %d, got %d", nonceLength*2, len(nonce1))
	}

	if nonce1 == nonce2 {
		t.Error("expected unique nonces")
	}
}

func TestParseWindowsUsername(t *testing.T) {
	tests := []struct {
		input          string
		expectedUser   string
		expectedDomain string
	}{
		{"admin", "admin", "."},
		{"DOMAIN\\admin", "admin", "DOMAIN"},
		{"admin@domain.com", "admin", "domain.com"},
		{".\\localuser", "localuser", "."},
	}

	for _, tt := range tests {
		user, domain := parseWindowsUsername(tt.input)
		if user != tt.expectedUser {
			t.Errorf("parseWindowsUsername(%q) user = %q, want %q", tt.input, user, tt.expectedUser)
		}
		if domain != tt.expectedDomain {
			t.Errorf("parseWindowsUsername(%q) domain = %q, want %q", tt.input, domain, tt.expectedDomain)
		}
	}
}
