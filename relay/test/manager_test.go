package test

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/relay/client"
	"github.com/netbirdio/netbird/relay/server"
)

func TestManager(t *testing.T) {
	addr := "localhost:1239"

	srv := server.NewServer()
	go func() {
		err := srv.Listen(addr)
		if err != nil {
			t.Fatalf("failed to bind server: %s", err)
		}
	}()

	defer func() {
		err := srv.Close()
		if err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cm := client.NewManager(ctx, addr, "me")
	cm.Serve()

	// wait for the relay handshake to complete
	time.Sleep(1 * time.Second)
	conn, err := cm.OpenConn("remotepeer")
	if err != nil {
		t.Errorf("failed to open connection: %s", err)
	}

	readCtx, readCancel := context.WithCancel(context.Background())
	defer readCancel()
	go func() {
		_, _ = conn.Read(make([]byte, 1))
		readCancel()
	}()

	cancel()

	select {
	case <-time.After(2 * time.Second):
		t.Errorf("client peer conn did not close automatically")
	case <-readCtx.Done():
		// conn exited well
	}
}
