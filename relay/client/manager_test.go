package client

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/relay/server"
	log "github.com/sirupsen/logrus"
)

func TestEmptyURL(t *testing.T) {
	mgr := NewManager(context.Background(), nil, "alice")
	err := mgr.Serve()
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestForeignConn(t *testing.T) {
	ctx := context.Background()

	srvCfg1 := server.ListenerConfig{
		Address: "localhost:1234",
	}
	srv1, err := server.NewServer(serverCfg)
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
		Address: "localhost:2234",
	}
	srv2, err := server.NewServer(serverCfg)
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

	idAlice := "alice"
	log.Debugf("connect by alice")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientAlice := NewManager(mCtx, toURL(srvCfg1), idAlice)
	err = clientAlice.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	idBob := "bob"
	log.Debugf("connect by bob")
	clientBob := NewManager(mCtx, toURL(srvCfg2), idBob)
	err = clientBob.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}
	bobsSrvAddr, err := clientBob.RelayInstanceAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}
	connAliceToBob, err := clientAlice.OpenConn(ctx, bobsSrvAddr, idBob)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}
	connBobToAlice, err := clientBob.OpenConn(ctx, bobsSrvAddr, idAlice)
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
		Address: "localhost:1234",
	}
	srv1, err := server.NewServer(serverCfg)
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
		Address: "localhost:2234",
	}
	srv2, err := server.NewServer(serverCfg)
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

	idAlice := "alice"
	log.Debugf("connect by alice")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	mgr := NewManager(mCtx, toURL(srvCfg1), idAlice)
	err = mgr.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}
	conn, err := mgr.OpenConn(ctx, toURL(srvCfg2)[0], "anotherpeer")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	err = conn.Close()
	if err != nil {
		t.Fatalf("failed to close connection: %s", err)
	}
}

func TestForeginAutoClose(t *testing.T) {
	ctx := context.Background()
	relayCleanupInterval = 1 * time.Second
	srvCfg1 := server.ListenerConfig{
		Address: "localhost:1234",
	}
	srv1, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		t.Log("binding server 1.")
		err := srv1.Listen(srvCfg1)
		if err != nil {
			errChan <- err
		}
	}()

	defer func() {
		t.Logf("closing server 1.")
		err := srv1.Shutdown(ctx)
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
		t.Logf("server 1. closed")
	}()

	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("failed to start server: %s", err)
	}

	srvCfg2 := server.ListenerConfig{
		Address: "localhost:2234",
	}
	srv2, err := server.NewServer(serverCfg)
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
	mgr := NewManager(mCtx, toURL(srvCfg1), idAlice)
	err = mgr.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	t.Log("open connection to another peer")
	conn, err := mgr.OpenConn(ctx, toURL(srvCfg2)[0], "anotherpeer")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	t.Log("close conn")
	err = conn.Close()
	if err != nil {
		t.Fatalf("failed to close connection: %s", err)
	}

	timeout := relayCleanupInterval + keepUnusedServerTime + 1*time.Second
	t.Logf("waiting for relay cleanup: %s", timeout)
	time.Sleep(timeout)
	if len(mgr.relayClients) != 0 {
		t.Errorf("expected 0, got %d", len(mgr.relayClients))
	}

	t.Logf("closing manager")
}

func TestAutoReconnect(t *testing.T) {
	ctx := context.Background()
	reconnectingTimeout = 2 * time.Second

	srvCfg := server.ListenerConfig{
		Address: "localhost:1234",
	}
	srv, err := server.NewServer(serverCfg)
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
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
	clientAlice := NewManager(mCtx, toURL(srvCfg), "alice")
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

	srvCfg1 := server.ListenerConfig{
		Address: "localhost:1234",
	}
	srv1, err := server.NewServer(serverCfg)
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

	idAlice := "alice"
	log.Debugf("connect by alice")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientAlice := NewManager(mCtx, toURL(srvCfg1), idAlice)
	err = clientAlice.Serve()
	if err != nil {
		t.Fatalf("failed to serve manager: %s", err)
	}

	conn1, err := clientAlice.OpenConn(ctx, clientAlice.ServerURLs()[0], "idBob")
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
