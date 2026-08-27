package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/netutil"
	"github.com/netbirdio/netbird/util/netrelay"
)

func testRelay(ctx context.Context, logger *log.Entry, src, dst net.Conn, idleTimeout time.Duration) (int64, int64) {
	return netrelay.Relay(ctx, src, dst, netrelay.Options{IdleTimeout: idleTimeout, Logger: logger})
}

func TestRelay_BidirectionalCopy(t *testing.T) {
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()

	logger := log.NewEntry(log.StandardLogger())
	ctx := context.Background()

	srcData := []byte("hello from src")
	dstData := []byte("hello from dst")

	// dst side: write response first, then read + close.
	go func() {
		_, _ = dstClient.Write(dstData)
		buf := make([]byte, 256)
		_, _ = dstClient.Read(buf)
		dstClient.Close()
	}()

	// src side: read the response, then send data + close.
	go func() {
		buf := make([]byte, 256)
		_, _ = srcClient.Read(buf)
		_, _ = srcClient.Write(srcData)
		srcClient.Close()
	}()

	s2d, d2s := testRelay(ctx, logger, srcServer, dstServer, 0)

	assert.Equal(t, int64(len(srcData)), s2d, "bytes src→dst")
	assert.Equal(t, int64(len(dstData)), d2s, "bytes dst→src")
}

func TestRelay_ContextCancellation(t *testing.T) {
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()
	defer srcClient.Close()
	defer dstClient.Close()

	logger := log.NewEntry(log.StandardLogger())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		testRelay(ctx, logger, srcServer, dstServer, 0)
		close(done)
	}()

	// Cancel should cause Relay to return.
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Relay did not return after context cancellation")
	}
}

func TestRelay_OneSideClosed(t *testing.T) {
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()
	defer dstClient.Close()

	logger := log.NewEntry(log.StandardLogger())
	ctx := context.Background()

	// Close src immediately. Relay should complete without hanging.
	srcClient.Close()

	done := make(chan struct{})
	go func() {
		testRelay(ctx, logger, srcServer, dstServer, 0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Relay did not return after one side closed")
	}
}

func TestRelay_LargeTransfer(t *testing.T) {
	srcClient, srcServer := net.Pipe()
	dstClient, dstServer := net.Pipe()

	logger := log.NewEntry(log.StandardLogger())
	ctx := context.Background()

	// 1MB of data.
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i % 256)
	}

	go func() {
		_, _ = srcClient.Write(data)
		srcClient.Close()
	}()

	errCh := make(chan error, 1)
	go func() {
		received, err := io.ReadAll(dstClient)
		if err != nil {
			errCh <- err
			return
		}
		if len(received) != len(data) {
			errCh <- fmt.Errorf("expected %d bytes, got %d", len(data), len(received))
			return
		}
		errCh <- nil
		dstClient.Close()
	}()

	s2d, _ := testRelay(ctx, logger, srcServer, dstServer, 0)
	assert.Equal(t, int64(len(data)), s2d, "should transfer all bytes")
	require.NoError(t, <-errCh)
}

func TestRelay_IdleTimeout(t *testing.T) {
	// Use real TCP connections so SetReadDeadline works (net.Pipe
	// does not support deadlines).
	srcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srcLn.Close()

	dstLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dstLn.Close()

	srcClient, err := net.Dial("tcp", srcLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer srcClient.Close()

	srcServer, err := srcLn.Accept()
	if err != nil {
		t.Fatal(err)
	}

	dstClient, err := net.Dial("tcp", dstLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dstClient.Close()

	dstServer, err := dstLn.Accept()
	if err != nil {
		t.Fatal(err)
	}

	logger := log.NewEntry(log.StandardLogger())
	ctx := context.Background()

	// Send initial data to prove the relay works.
	go func() {
		_, _ = srcClient.Write([]byte("ping"))
	}()

	done := make(chan struct{})
	var s2d, d2s int64
	go func() {
		s2d, d2s = testRelay(ctx, logger, srcServer, dstServer, 200*time.Millisecond)
		close(done)
	}()

	// Read the forwarded data on the dst side.
	buf := make([]byte, 64)
	n, err := dstClient.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))

	// Now stop sending. The relay should close after the idle timeout.
	select {
	case <-done:
		assert.Greater(t, s2d, int64(0), "should have transferred initial data")
		_ = d2s
	case <-time.After(5 * time.Second):
		t.Fatal("Relay did not exit after idle timeout")
	}
}

func TestIsExpectedError(t *testing.T) {
	assert.True(t, netutil.IsExpectedError(net.ErrClosed))
	assert.True(t, netutil.IsExpectedError(context.Canceled))
	assert.True(t, netutil.IsExpectedError(io.EOF))
	assert.False(t, netutil.IsExpectedError(io.ErrUnexpectedEOF))
}
