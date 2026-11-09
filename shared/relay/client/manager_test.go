package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
)

// newManagerTestServerConfig creates a new server config for manager testing with the given address
func newManagerTestServerConfig(address string) server.Config {
	return server.Config{
		Meter:          otel.Meter(""),
		ExposedAddress: address,
		TLSSupport:     false,
		AuthValidator:  &allow.Auth{},
	}
}

func TestEmptyURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(ctx, nil, "alice", iface.DefaultMTU)
	err := mgr.Serve()
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestForeignConn(t *testing.T) {
	ctx := context.Background()

	lstCfg1 := server.ListenerConfig{
		Address: "localhost:52101",
	}

	srv1, err := server.NewServer(newManagerTestServerConfig(lstCfg1.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv1.Listen(lstCfg1)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv1.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	srvCfg2 := server.ListenerConfig{
		Address: "localhost:52102",
	}
	srv2, err := server.NewServer(newManagerTestServerConfig(srvCfg2.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan2 := make(chan error, 1)
	go func() {
		err := srv2.Listen(srvCfg2)
		if err != nil {
			errChan2 <- err
		}
	}()

	defer func() {
		err := srv2.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	if err := waitForServerToStart(errChan2); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientAlice := NewManager(mCtx, toURL(lstCfg1), "alice", iface.DefaultMTU)
	if err := clientAlice.Serve(); err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	clientBob := NewManager(mCtx, toURL(srvCfg2), "bob", iface.DefaultMTU)
	if err := clientBob.Serve(); err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}
	bobsSrvAddr, _, err := clientBob.RelayInstanceAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}
	connAliceToBob, err := clientAlice.OpenConn(ctx, bobsSrvAddr, "bob", netip.Addr{})
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}
	connBobToAlice, err := clientBob.OpenConn(ctx, bobsSrvAddr, "alice", netip.Addr{})
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	payload := "hello bob, I am alice"
	_, err = connAliceToBob.Write([]byte(payload))
	if err != nil {
		t.Fatalf("failed to write to channel: %s", err)
	}

	buf := make([]byte, 65535)
	n, err := connBobToAlice.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from channel: %s", err)
	}

	_, err = connBobToAlice.Write(buf[:n])
	if err != nil {
		t.Fatalf("failed to write to channel: %s", err)
	}

	n, err = connAliceToBob.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from channel: %s", err)
	}

	if payload != string(buf[:n]) {
		t.Fatalf("expected %s, got %s", payload, string(buf[:n]))
	}
}

func TestForeginConnClose(t *testing.T) {
	ctx := context.Background()

	srvCfg1 := server.ListenerConfig{
		Address: "localhost:52201",
	}
	srv1, err := server.NewServer(newManagerTestServerConfig(srvCfg1.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv1.Listen(srvCfg1)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv1.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	srvCfg2 := server.ListenerConfig{
		Address: "localhost:52202",
	}
	srv2, err := server.NewServer(newManagerTestServerConfig(srvCfg2.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan2 := make(chan error, 1)
	go func() {
		err := srv2.Listen(srvCfg2)
		if err != nil {
			errChan2 <- err
		}
	}()

	defer func() {
		err := srv2.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	if err := waitForServerToStart(errChan2); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	mgrBob := NewManager(mCtx, toURL(srvCfg2), "bob", iface.DefaultMTU)
	if err := mgrBob.Serve(); err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	mgr := NewManager(mCtx, toURL(srvCfg1), "alice", iface.DefaultMTU)
	err = mgr.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}
	conn, err := mgr.OpenConn(ctx, toURL(srvCfg2)[0], "bob", netip.Addr{})
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	err = conn.Close()
	if err != nil {
		t.Fatalf("failed to close connection: %s", err)
	}
}

func TestForeignAutoClose(t *testing.T) {
	ctx := context.Background()
	relayCleanupInterval = 1 * time.Second
	keepUnusedServerTime = 2 * time.Second

	srvCfg1 := server.ListenerConfig{
		Address: "localhost:52301",
	}
	srv1, err := server.NewServer(newManagerTestServerConfig(srvCfg1.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		t.Log("binding server 1.")
		if err := srv1.Listen(srvCfg1); err != nil {
			errChan <- err
		}
	}()

	defer func() {
		t.Logf("closing server 1.")
		if err := srv1.Shutdown(ctx); err != nil {
			t.Errorf("failed to close server: %s", err)
		}
		t.Logf("server 1. closed")
	}()

	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	srvCfg2 := server.ListenerConfig{
		Address: "localhost:52302",
	}
	srv2, err := server.NewServer(newManagerTestServerConfig(srvCfg2.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan2 := make(chan error, 1)
	go func() {
		t.Log("binding server 2.")
		err := srv2.Listen(srvCfg2)
		if err != nil {
			errChan2 <- err
		}
	}()
	defer func() {
		t.Logf("closing server 2.")
		err := srv2.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
		t.Logf("server 2 closed.")
	}()

	if err := waitForServerToStart(errChan2); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	idAlice := "alice"
	t.Log("connect to server 1.")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	mgr := NewManager(mCtx, toURL(srvCfg1), idAlice, iface.DefaultMTU)
	err = mgr.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	foreignServerURL := toURL(srvCfg2)[0]

	t.Log("open connection to another peer")
	if _, err = mgr.OpenConn(ctx, foreignServerURL, "anotherpeer", netip.Addr{}); err == nil {
		t.Fatalf("should have failed to open connection to another peer")
	}

	timeout := relayCleanupInterval + keepUnusedServerTime + 2*time.Second
	t.Logf("waiting for relay cleanup: %s", timeout)
	deadline := time.After(timeout)
	for {
		mgr.relayClientsMutex.RLock()
		_, tracked := mgr.relayClients[foreignServerURL]
		mgr.relayClientsMutex.RUnlock()
		if !tracked {
			t.Log("foreign relay connection cleaned up successfully")
			break
		}
		select {
		case <-deadline:
			t.Fatal("foreign relay was not cleaned up")
		case <-time.After(200 * time.Millisecond):
		}
	}

	t.Logf("closing manager")
}

func TestAutoReconnect(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{
		Address: "localhost:52401",
	}
	srv, err := server.NewServer(newManagerTestServerConfig(srvCfg.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(srvCfg); err != nil {
			errChan <- err
		}
	}()

	defer func() {
		err := srv.Shutdown(ctx)
		if err != nil {
			log.Errorf("failed to close server: %s", err)
		}
	}()

	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	clientBob := NewManager(mCtx, toURL(srvCfg), "bob", iface.DefaultMTU)
	err = clientBob.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	clientAlice := NewManager(mCtx, toURL(srvCfg), "alice", iface.DefaultMTU,
		WithMaxBackoffInterval(2*time.Second))
	err = clientAlice.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}
	ra, _, err := clientAlice.RelayInstanceAddress()
	if err != nil {
		t.Errorf("failed to get relay address: %s", err)
	}
	conn, err := clientAlice.OpenConn(ctx, ra, "bob", netip.Addr{})
	if err != nil {
		t.Errorf("failed to bind channel: %s", err)
	}

	t.Log("closing client relay connection")
	// todo figure out moc server
	_ = clientAlice.relayClient.relayConn.Close()
	t.Log("start test reading")
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Errorf("unexpected reading from closed connection")
	}

	log.Infof("waiting for reconnection")
	if err := waitForReady(ctx, clientAlice, 15*time.Second); err != nil {
		t.Fatalf("manager did not reconnect: %s", err)
	}

	log.Infof("reopent the connection")
	_, err = clientAlice.OpenConn(ctx, ra, "bob", netip.Addr{})
	if err != nil {
		t.Errorf("failed to open channel: %s", err)
	}
}

func waitForReady(ctx context.Context, m *Manager, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.Ready() {
			return nil
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("manager not ready within %s", timeout)
}

func toURL(address server.ListenerConfig) []string {
	return []string{"rel://" + address.Address}
}

func TestConnContextCancelledOnServerDisconnect(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: "localhost:52601"}
	srv, err := server.NewServer(newManagerTestServerConfig(srvCfg.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(srvCfg); err != nil {
			errChan <- err
		}
	}()
	defer func() {
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	mgrBob := NewManager(mCtx, toURL(srvCfg), "bob", iface.DefaultMTU)
	if err := mgrBob.Serve(); err != nil {
		t.Fatalf("failed to serve bob manager: %s", err)
	}

	mgr := NewManager(mCtx, toURL(srvCfg), "alice", iface.DefaultMTU)
	if err := mgr.Serve(); err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	ra, _, err := mgr.RelayInstanceAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}

	relayedConn, err := mgr.OpenConn(ctx, ra, "bob", netip.Addr{})
	if err != nil {
		t.Fatalf("failed to open conn: %s", err)
	}

	select {
	case <-relayedConn.Context().Done():
		t.Fatal("conn context cancelled while the relay is still up")
	default:
	}

	_ = mgr.relayClient.relayConn.Close()

	select {
	case <-relayedConn.Context().Done():
	case <-time.After(15 * time.Second):
		t.Fatal("conn context was not cancelled after the relay connection dropped")
	}

	if cause := context.Cause(relayedConn.Context()); !errors.Is(cause, ErrServerDisconnected) {
		t.Errorf("unexpected cancellation cause: %v, want %v", cause, ErrServerDisconnected)
	}
}

func TestConnContextCauseOnLocalClose(t *testing.T) {
	ctx := context.Background()

	srvCfg := server.ListenerConfig{Address: "localhost:52602"}
	srv, err := server.NewServer(newManagerTestServerConfig(srvCfg.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(srvCfg); err != nil {
			errChan <- err
		}
	}()
	defer func() {
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	mgrBob := NewManager(mCtx, toURL(srvCfg), "bob", iface.DefaultMTU)
	if err := mgrBob.Serve(); err != nil {
		t.Fatalf("failed to serve bob manager: %s", err)
	}

	mgr := NewManager(mCtx, toURL(srvCfg), "alice", iface.DefaultMTU)
	if err := mgr.Serve(); err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	ra, _, err := mgr.RelayInstanceAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}

	relayedConn, err := mgr.OpenConn(ctx, ra, "bob", netip.Addr{})
	if err != nil {
		t.Fatalf("failed to open conn: %s", err)
	}

	if err := relayedConn.Close(); err != nil {
		t.Fatalf("failed to close conn: %s", err)
	}

	select {
	case <-relayedConn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("conn context was not cancelled after a local close")
	}

	if cause := context.Cause(relayedConn.Context()); !errors.Is(cause, net.ErrClosed) {
		t.Errorf("unexpected cancellation cause after a local close: %v, want %v", cause, net.ErrClosed)
	}
}
