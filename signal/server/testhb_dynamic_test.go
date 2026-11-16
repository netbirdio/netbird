package server

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/shared/testhb"
)

// timedStream records when each heartbeat was sent.
type timedStream struct {
	*hbStream
	mu  sync.Mutex
	hbs []time.Time
}

func (s *timedStream) Send(m *proto.EncryptedMessage) error {
	if m.Key == TestHeartbeatKey {
		s.mu.Lock()
		s.hbs = append(s.hbs, time.Now())
		s.mu.Unlock()
	}
	return s.hbStream.Send(m)
}

func (s *timedStream) times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.hbs...)
}

func connectTestPeer(t *testing.T, s *Server, peerKey string, pairs ...string) *timedStream {
	t.Helper()
	md := metadata.Pairs(append([]string{proto.HeaderId, peerKey}, pairs...)...)
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), md))
	stream := &timedStream{hbStream: &hbStream{ctx: ctx}}
	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, func() bool { return s.registry.IsPeerRegistered(peerKey) }, time.Second, 10*time.Millisecond)
	return stream
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestConnectStreamDynamicHeartbeat(t *testing.T) {
	modePath := filepath.Join(t.TempDir(), "mode")
	writeTestFile(t, modePath, "dynamic\n")
	t.Setenv("NB_TEST_HB_MODE_FILE", modePath)

	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	// Client clock 200 ms behind arrival, phase 300 ms, period 2 s: the server
	// fires when (w - 200) mod 2000 == 300, so at w mod 2000 == 500.
	value := "p=300;period=2;t=" + strconv.FormatInt(time.Now().UnixMilli()-200, 10)
	stream := connectTestPeer(t, s, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDE=", testhb.MetadataKey, value)

	require.Eventually(t, func() bool { return len(stream.times()) >= 2 }, 5*time.Second, 20*time.Millisecond)
	ts := stream.times()
	for i, at := range ts {
		got := at.UnixMilli() % 2000
		assert.True(t, got >= 495 && got < 600, "heartbeat %d at ms %d mod 2000, want 500", i, got)
	}
	assert.InDelta(t, 2000, ts[1].Sub(ts[0]).Milliseconds(), 100, "heartbeats one client period apart")
}

func TestConnectStreamDynamicWithoutValueSilent(t *testing.T) {
	modePath := filepath.Join(t.TempDir(), "mode")
	writeTestFile(t, modePath, "dynamic\n")
	t.Setenv("NB_TEST_HB_MODE_FILE", modePath)

	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	stream := connectTestPeer(t, s, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDI=")

	time.Sleep(2500 * time.Millisecond)
	assert.Empty(t, stream.times(), "dynamic without a client value must not send heartbeats")
}

func TestConnectStreamMuteSignal(t *testing.T) {
	mutePath := filepath.Join(t.TempDir(), "mute")
	t.Setenv("NB_TEST_HB_MUTE_FILE", mutePath)

	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	stream := connectTestPeer(t, s, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDM=")

	require.Eventually(t, func() bool { return len(stream.times()) >= 1 }, 3*time.Second, 20*time.Millisecond)

	writeTestFile(t, mutePath, "signal\n")
	time.Sleep(1100 * time.Millisecond) // let a tick planned before the mute pass
	n := len(stream.times())
	time.Sleep(2100 * time.Millisecond)
	assert.Equal(t, n, len(stream.times()), "muted signal must not send heartbeats")

	writeTestFile(t, mutePath, "")
	require.Eventually(t, func() bool { return len(stream.times()) > n }, 3*time.Second, 20*time.Millisecond,
		"heartbeats must resume after unmute")
}

func TestSignalBlackholeDropsForwarded(t *testing.T) {
	mutePath := filepath.Join(t.TempDir(), "mute")
	t.Setenv("NB_TEST_HB_MUTE_FILE", mutePath)

	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDQ="
	stream := connectTestPeer(t, s, peerKey)

	forwarded := func() int {
		stream.hbStream.mu.Lock()
		defer stream.hbStream.mu.Unlock()
		n := 0
		for _, m := range stream.hbStream.msgs {
			if m.Key == "sender" {
				n++
			}
		}
		return n
	}
	msg := &proto.EncryptedMessage{Key: "sender", RemoteKey: peerKey}

	writeTestFile(t, mutePath, "signal-blackhole\n")
	_, err = s.Send(context.Background(), msg)
	require.NoError(t, err, "blackholed Send must still succeed for the sender")
	assert.Equal(t, 0, forwarded(), "blackhole must drop the forwarded message")

	// A self-probe is a Send to the peer's own key.
	_, err = s.Send(context.Background(), &proto.EncryptedMessage{Key: peerKey, RemoteKey: peerKey})
	require.NoError(t, err)
	time.Sleep(1500 * time.Millisecond)
	assert.Empty(t, stream.times(), "blackhole must mute signal heartbeats")
	stream.hbStream.mu.Lock()
	assert.Empty(t, stream.hbStream.msgs, "blackhole must deliver nothing")
	stream.hbStream.mu.Unlock()

	writeTestFile(t, mutePath, "")
	_, err = s.Send(context.Background(), msg)
	require.NoError(t, err)
	assert.Equal(t, 1, forwarded(), "forwarding must resume after the blackhole is removed")
}
