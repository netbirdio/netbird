package client

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server"
)

func TestForeignConn(t *testing.T) {
	ctx := context.Background()

	srvCfg1 := server.ListenerConfig{
		Address: "localhost:1234",
	}
	srv1 := server.NewServer(srvCfg1.Address, false)
	go func() {
		err := srv1.Listen(srvCfg1)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv1.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	srvCfg2 := server.ListenerConfig{
		Address: "localhost:2234",
	}
	srv2 := server.NewServer(srvCfg2.Address, false)
	go func() {
		err := srv2.Listen(srvCfg2)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv2.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	idAlice := "alice"
	log.Debugf("connect by alice")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientAlice := NewManager(mCtx, srvCfg1.Address, idAlice)
	clientAlice.Serve()

	idBob := "bob"
	log.Debugf("connect by bob")
	clientBob := NewManager(mCtx, srvCfg2.Address, idBob)
	clientBob.Serve()

	bobsSrvAddr, err := clientBob.RelayInstanceAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}
	connAliceToBob, err := clientAlice.OpenConn(bobsSrvAddr, idBob, nil)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}
	connBobToAlice, err := clientBob.OpenConn(bobsSrvAddr, idAlice, nil)
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
	srv1 := server.NewServer(srvCfg1.Address, false)
	go func() {
		err := srv1.Listen(srvCfg1)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv1.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	srvCfg2 := server.ListenerConfig{
		Address: "localhost:2234",
	}
	srv2 := server.NewServer(srvCfg2.Address, false)
	go func() {
		err := srv2.Listen(srvCfg2)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv2.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()

	idAlice := "alice"
	log.Debugf("connect by alice")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	mgr := NewManager(mCtx, srvCfg1.Address, idAlice)
	mgr.Serve()

	conn, err := mgr.OpenConn(srvCfg2.Address, "anotherpeer", nil)
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
	srv1 := server.NewServer(srvCfg1.Address, false)
	go func() {
		t.Log("binding server 1.")
		err := srv1.Listen(srvCfg1)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		t.Logf("closing server 1.")
		err := srv1.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
		t.Logf("server 1. closed")
	}()

	srvCfg2 := server.ListenerConfig{
		Address: "localhost:2234",
	}
	srv2 := server.NewServer(srvCfg2.Address, false)
	go func() {
		t.Log("binding server 2.")
		err := srv2.Listen(srvCfg2)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()
	defer func() {
		t.Logf("closing server 2.")
		err := srv2.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
		t.Logf("server 2 closed.")
	}()

	idAlice := "alice"
	t.Log("connect to server 1.")
	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	mgr := NewManager(mCtx, srvCfg1.Address, idAlice)
	mgr.Serve()

	t.Log("open connection to another peer")
	conn, err := mgr.OpenConn(srvCfg2.Address, "anotherpeer", nil)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	t.Log("close conn")
	err = conn.Close()
	if err != nil {
		t.Fatalf("failed to close connection: %s", err)
	}

	t.Logf("waiting for relay cleanup: %s", relayCleanupInterval+1*time.Second)
	time.Sleep(relayCleanupInterval + 1*time.Second)
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
	srv := server.NewServer(srvCfg.Address, false)
	go func() {
		err := srv.Listen(srvCfg)
		if err != nil {
			t.Errorf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			log.Errorf("failed to close server: %s", err)
		}
	}()

	mCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientAlice := NewManager(mCtx, srvCfg.Address, "alice")
	clientAlice.Serve()
	ra, err := clientAlice.RelayInstanceAddress()
	if err != nil {
		t.Errorf("failed to get relay address: %s", err)
	}
	conn, err := clientAlice.OpenConn(ra, "bob", nil)
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
	_, err = clientAlice.OpenConn(ra, "bob", nil)
	if err != nil {
		t.Errorf("failed to open channel: %s", err)
	}
}
