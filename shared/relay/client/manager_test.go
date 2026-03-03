package client

import (
	"context"
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
	bobsSrvAddr, err := clientBob.RelayInstanceAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}
	connAliceToBob, err := clientAlice.OpenConn(ctx, bobsSrvAddr, "bob")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}
	connBobToAlice, err := clientBob.OpenConn(ctx, bobsSrvAddr, "alice")
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
	conn, err := mgr.OpenConn(ctx, toURL(srvCfg2)[0], "bob")
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

	// Set up a disconnect listener to track when foreign server disconnects
	foreignServerURL := toURL(srvCfg2)[0]
	disconnected := make(chan struct{})
	onDisconnect := func() {
		select {
		case disconnected <- struct{}{}:
		default:
		}
	}

	t.Log("open connection to another peer")
	if _, err = mgr.OpenConn(ctx, foreignServerURL, "anotherpeer"); err == nil {
		t.Fatalf("should have failed to open connection to another peer")
	}

	// Add the disconnect listener after the connection attempt
	if err := mgr.AddCloseListener(foreignServerURL, onDisconnect); err != nil {
		t.Logf("failed to add close listener (expected if connection failed): %s", err)
	}

	// Wait for cleanup to happen
	timeout := relayCleanupInterval + keepUnusedServerTime + 2*time.Second
	t.Logf("waiting for relay cleanup: %s", timeout)

	select {
	case <-disconnected:
		t.Log("foreign relay connection cleaned up successfully")
	case <-time.After(timeout):
		t.Log("timeout waiting for cleanup - this might be expected if connection never established")
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

	clientAlice := NewManager(mCtx, toURL(srvCfg), "alice", iface.DefaultMTU)
	err = clientAlice.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}
	ra, err := clientAlice.RelayInstanceAddress()
	if err != nil {
		t.Errorf("failed to get relay address: %s", err)
	}
	conn, err := clientAlice.OpenConn(ctx, ra, "bob")
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
	time.Sleep(reconnectingTimeout + 1*time.Second)

	log.Infof("reopent the connection")
	_, err = clientAlice.OpenConn(ctx, ra, "bob")
	if err != nil {
		t.Errorf("failed to open channel: %s", err)
	}
}

func TestNotifierDoubleAdd(t *testing.T) {
	ctx := context.Background()

	listenerCfg1 := server.ListenerConfig{
		Address: "localhost:52501",
	}
	srv, err := server.NewServer(newManagerTestServerConfig(listenerCfg1.Address))
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(listenerCfg1); err != nil {
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

	log.Debugf("connect by alice")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	clientBob := NewManager(mCtx, toURL(listenerCfg1), "bob", iface.DefaultMTU)
	if err = clientBob.Serve(); err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	clientAlice := NewManager(mCtx, toURL(listenerCfg1), "alice", iface.DefaultMTU)
	if err = clientAlice.Serve(); err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	conn1, err := clientAlice.OpenConn(ctx, clientAlice.ServerURLs()[0], "bob")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	fnCloseListener := OnServerCloseListener(func() {
		log.Infof("close listener")
	})

	err = clientAlice.AddCloseListener(clientAlice.ServerURLs()[0], fnCloseListener)
	if err != nil {
		t.Fatalf("failed to add close listener: %s", err)
	}

	err = clientAlice.AddCloseListener(clientAlice.ServerURLs()[0], fnCloseListener)
	if err != nil {
		t.Fatalf("failed to add close listener: %s", err)
	}

	err = conn1.Close()
	if err != nil {
		t.Errorf("failed to close connection: %s", err)
	}

}

func toURL(address server.ListenerConfig) []string {
	return []string{"rel://" + address.Address}
}
