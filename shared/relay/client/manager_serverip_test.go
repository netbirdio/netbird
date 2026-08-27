package client

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
)

// TestManager_ForeignRelayServerIP exercises the foreign-relay path
// end-to-end through Manager.OpenConn. Alice and Bob register on different
// relay servers; Alice dials Bob's foreign relay using an unresolvable
// FQDN. Without a server IP the dial fails; with Bob's advertised IP it
// recovers and a payload round-trips between the peers.
func TestManager_ForeignRelayServerIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Alice's home relay
	homeCfg := server.ListenerConfig{Address: "127.0.0.1:52401"}
	homeSrv, err := server.NewServer(newManagerTestServerConfig(homeCfg.Address))
	if err != nil {
		t.Fatalf("create home server: %s", err)
	}
	homeErr := make(chan error, 1)
	go func() {
		if err := homeSrv.Listen(homeCfg); err != nil {
			homeErr <- err
		}
	}()
	t.Cleanup(func() { _ = homeSrv.Shutdown(context.Background()) })
	if err := waitForServerToStart(homeErr); err != nil {
		t.Fatalf("home server: %s", err)
	}

	// Bob's foreign relay
	foreignCfg := server.ListenerConfig{Address: "127.0.0.1:52402"}
	foreignSrv, err := server.NewServer(newManagerTestServerConfig(foreignCfg.Address))
	if err != nil {
		t.Fatalf("create foreign server: %s", err)
	}
	foreignErr := make(chan error, 1)
	go func() {
		if err := foreignSrv.Listen(foreignCfg); err != nil {
			foreignErr <- err
		}
	}()
	t.Cleanup(func() { _ = foreignSrv.Shutdown(context.Background()) })
	if err := waitForServerToStart(foreignErr); err != nil {
		t.Fatalf("foreign server: %s", err)
	}

	mCtx, mCancel := context.WithCancel(ctx)
	t.Cleanup(mCancel)

	mgrAlice := NewManager(mCtx, toURL(homeCfg), "alice", iface.DefaultMTU)
	if err := mgrAlice.Serve(); err != nil {
		t.Fatalf("alice manager serve: %s", err)
	}

	mgrBob := NewManager(mCtx, toURL(foreignCfg), "bob", iface.DefaultMTU)
	if err := mgrBob.Serve(); err != nil {
		t.Fatalf("bob manager serve: %s", err)
	}

	// Bob's real relay URL and the IP that would ride along in signal as relayServerIP.
	bobRealAddr, bobAdvertisedIP, err := mgrBob.RelayInstanceAddress()
	if err != nil {
		t.Fatalf("bob relay address: %s", err)
	}
	if !bobAdvertisedIP.IsValid() {
		t.Fatalf("expected valid RelayInstanceIP for bob, got zero")
	}

	// .invalid is reserved (RFC 2606), so DNS resolution always fails.
	const brokenFQDN = "rel://relay-bob-instance.invalid:52402"
	if brokenFQDN == bobRealAddr {
		t.Fatalf("broken FQDN must differ from bob's real address (%s)", bobRealAddr)
	}

	t.Run("no server IP, dial fails", func(t *testing.T) {
		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
		defer dialCancel()
		_, err := mgrAlice.OpenConn(dialCtx, brokenFQDN, "bob", netip.Addr{})
		if err == nil {
			t.Fatalf("expected OpenConn to fail without server IP, got success")
		}
	})

	t.Run("server IP recovers", func(t *testing.T) {
		// Bob waits for Alice's incoming peer connection on his side.
		bobSideCh := make(chan error, 1)
		go func() {
			conn, err := mgrBob.OpenConn(ctx, bobRealAddr, "alice", netip.Addr{})
			if err != nil {
				bobSideCh <- err
				return
			}
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				bobSideCh <- err
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				bobSideCh <- err
				return
			}
			bobSideCh <- nil
		}()

		aliceConn, err := mgrAlice.OpenConn(ctx, brokenFQDN, "bob", bobAdvertisedIP)
		if err != nil {
			t.Fatalf("alice OpenConn with server IP: %s", err)
		}
		t.Cleanup(func() { _ = aliceConn.Close() })

		payload := []byte("alice-to-bob")
		if _, err := aliceConn.Write(payload); err != nil {
			t.Fatalf("alice write: %s", err)
		}

		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(aliceConn, buf); err != nil {
			t.Fatalf("alice read echo: %s", err)
		}
		if string(buf) != string(payload) {
			t.Fatalf("echo mismatch: got %q want %q", buf, payload)
		}

		select {
		case err := <-bobSideCh:
			if err != nil {
				t.Fatalf("bob side: %s", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for bob side")
		}
	})
}
