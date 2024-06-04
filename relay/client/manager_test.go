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
	clientAlice := NewManager(ctx, addr1, idAlice)
	clientAlice.Serve()

	idBob := "bob"
	log.Debugf("connect by bob")
	clientBob := NewManager(ctx, addr2, idBob)
	clientBob.Serve()

	bobsSrvAddr, err := clientBob.RelayAddress()
	if err != nil {
		t.Fatalf("failed to get relay address: %s", err)
	}
	connAliceToBob, err := clientAlice.OpenConn(bobsSrvAddr.String(), idBob)
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}
	connBobToAlice, err := clientBob.OpenConn(bobsSrvAddr.String(), idAlice)
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
	clientAlice := NewManager(ctx, addr1, idAlice)
	clientAlice.Serve()

	conn, err := clientAlice.OpenConn(addr2, "anotherpeer")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	err = conn.Close()
	if err != nil {
		t.Fatalf("failed to close connection: %s", err)
	}

	select {}
}

func TestForeginAutoClose(t *testing.T) {
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
	mgr := NewManager(ctx, addr1, idAlice)
	relayCleanupInterval = 2 * time.Second
	mgr.Serve()

	conn, err := mgr.OpenConn(addr2, "anotherpeer")
	if err != nil {
		t.Fatalf("failed to bind channel: %s", err)
	}

	err = conn.Close()
	if err != nil {
		t.Fatalf("failed to close connection: %s", err)
	}

	time.Sleep(relayCleanupInterval + 1*time.Second)
	if len(mgr.relayClients) != 0 {
		t.Errorf("expected 0, got %d", len(mgr.relayClients))
	}
}
