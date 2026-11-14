package grpc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// acceptedConn returns the server end of a loopback TCP connection.
func acceptedConn(t *testing.T) net.Conn {
	t.Helper()
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	srv, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func idleOf(t *testing.T, c net.Conn) time.Duration {
	t.Helper()
	idle, err := keepalive.Idle(c)
	require.NoError(t, err)
	return idle
}

// runHandler runs HandleUpdates for a stream on conn and returns the func that
// ends the stream and waits for the handler.
func runHandler(t *testing.T, conn net.Conn, aligned *alignedHeartbeat) func() {
	t.Helper()
	srvCtx, cancel := context.WithCancel(keepalive.ConnContext(context.Background(), conn))
	srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 16)}
	pu, secretsManager := newHeartbeatTestHandler(t, srv)
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(mustGenerateKey(t), nil)
	pu.WithAlignedHeartbeat(aligned, nil)
	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(srvCtx) }()
	return func() {
		cancel()
		if err := <-done; err != nil {
			assert.True(t, errors.Is(err, context.Canceled), "handler ended with %v", err)
		}
	}
}

// An aligned Sync stream moves the keepalive of its connection past the period
// and restores it when it ends. A stock stream leaves it as accepted.
func TestHandleUpdates_AlignedKeepAlive(t *testing.T) {
	conn := acceptedConn(t)
	stock := idleOf(t, conn)

	end := runHandler(t, conn, &alignedHeartbeat{
		answer: alignedhb.Answer{Period: time.Minute, Phase: time.Second},
		signed: alignedhb.SignedPhase{Phase: time.Second, Day: phasesig.Day(time.Now())},
	})
	assert.Eventually(t, func() bool { return idleOf(t, conn) == 2*time.Minute }, 2*time.Second, 10*time.Millisecond,
		"aligned stream: idle twice the period")
	end()
	assert.Equal(t, stock, idleOf(t, conn), "the ended stream restores the stock keepalive")

	end = runHandler(t, conn, nil)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, stock, idleOf(t, conn), "stock stream must not touch the keepalive")
	end()
}
