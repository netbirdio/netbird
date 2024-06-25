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

	addr1 := "localhost:1234"
	srv1 := server.NewServer()
	go func() {
		err := srv1.Listen(addr1)
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

	addr2 := "localhost:2234"
	srv2 := server.NewServer()
	go func() {
		err := srv2.Listen(addr2)
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
	clientAlice := NewManager(mCtx, addr1, idAlice)
	clientAlice.Serve()

	idBob := "bob"
	log.Debugf("connect by bob")
	clientBob := NewManager(mCtx, addr2, idBob)
	clientBob.Serve()

	bobsSrvAddr, err := clientBob.RelayAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}
	connAliceToBob, err := clientAlice.OpenConn(bobsSrvAddr.String(), idBob, nil)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}
	connBobToAlice, err := clientBob.OpenConn(bobsSrvAddr.String(), idAlice, nil)
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

	addr1 := "localhost:1234"
	srv1 := server.NewServer()
	go func() {
		err := srv1.Listen(addr1)
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

	addr2 := "localhost:2234"
	srv2 := server.NewServer()
	go func() {
		err := srv2.Listen(addr2)
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
	mgr := NewManager(mCtx, addr1, idAlice)
	mgr.Serve()

	conn, err := mgr.OpenConn(addr2, "anotherpeer", nil)
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
	addr1 := "localhost:1234"
	srv1 := server.NewServer()
	go func() {
		t.Log("binding server 1.")
		err := srv1.Listen(addr1)
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

	addr2 := "localhost:2234"
	srv2 := server.NewServer()
	go func() {
		t.Log("binding server 2.")
		err := srv2.Listen(addr2)
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
	mgr := NewManager(mCtx, addr1, idAlice)
	mgr.Serve()

	t.Log("open connection to another peer")
	conn, err := mgr.OpenConn(addr2, "anotherpeer", nil)
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

	addr := "localhost:1234"
	srv := server.NewServer()
	go func() {
		err := srv.Listen(addr)
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
	clientAlice := NewManager(mCtx, addr, "alice")
	clientAlice.Serve()
	ra, err := clientAlice.RelayAddress()
	if err != nil {
		t.Errorf("failed to get relay address: %s", err)
	}
	conn, err := clientAlice.OpenConn(ra.String(), "bob", nil)
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
	_, err = clientAlice.OpenConn(ra.String(), "bob", nil)
	if err != nil {
		t.Errorf("failed to open channel: %s", err)
	}
}
