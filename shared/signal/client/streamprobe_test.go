package client

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

// blockingSender holds every Send until release is closed, like a stream stuck
// on flow control, and records the frames and the highest overlap seen.
type blockingSender struct {
	release  chan struct{}
	inflight atomic.Int32
	maxSeen  atomic.Int32
	mu       sync.Mutex
	frames   []*proto.EncryptedMessage
}

func (b *blockingSender) Send(m *proto.EncryptedMessage) error {
	n := b.inflight.Add(1)
	for {
		old := b.maxSeen.Load()
		if n <= old || b.maxSeen.CompareAndSwap(old, n) {
			break
		}
	}
	<-b.release
	b.mu.Lock()
	b.frames = append(b.frames, m)
	b.mu.Unlock()
	b.inflight.Add(-1)
	return nil
}

func (b *blockingSender) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.frames)
}

// The watchdog writes on the stream so a proxy holding a dead stream ends it.
// A blocked write must not stall the caller, and a second probe while the first
// is stuck must not start an overlapping Send.
func TestSendStreamProbeWritesOnStreamWithoutOverlap(t *testing.T) {
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: key}
	sender := &blockingSender{release: make(chan struct{})}
	c.phase.Store(newPhaseWriter(sender, &c.streamSendMu, messages.PeerID{}, key.PublicKey().String(), time.Minute, 0))
	var inflight atomic.Bool

	returned := make(chan struct{})
	go func() {
		c.sendStreamProbe(sender, &inflight)
		c.sendStreamProbe(sender, &inflight)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("sendStreamProbe blocked on a stuck stream")
	}

	close(sender.release)
	require.Eventually(t, func() bool { return !inflight.Load() }, time.Second, 5*time.Millisecond)
	assert.Equal(t, 1, sender.count(), "a probe while one is in flight must be skipped")
	assert.Equal(t, int32(1), sender.maxSeen.Load(), "stream sends must never overlap")

	frame := sender.frames[0]
	assert.Equal(t, key.PublicKey().String(), frame.Key, "probe must come from self")
	assert.Equal(t, key.PublicKey().String(), frame.RemoteKey, "probe must be addressed to self")
	assert.Nil(t, frame.ServerHeartbeat, "probe must not look like a server heartbeat")
	assert.Nil(t, frame.Body, "probe must carry no body")

	c.sendStreamProbe(sender, &inflight)
	require.Eventually(t, func() bool { return sender.count() == 2 }, time.Second, 5*time.Millisecond,
		"a new probe must go out once the previous one finished")
}

// A stock server never reads the stream, so stream probes there would fill the
// flow control window. Without the aligned heartbeat answer nothing is written.
func TestSendStreamProbeSkipsStreamWithoutAnswer(t *testing.T) {
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: key}
	sender := &blockingSender{release: make(chan struct{})}
	close(sender.release)
	var inflight atomic.Bool

	c.sendStreamProbe(sender, &inflight)

	assert.False(t, inflight.Load(), "no probe must be in flight on a stock stream")
	assert.Never(t, func() bool { return sender.count() > 0 }, 200*time.Millisecond, 10*time.Millisecond,
		"no frame must be written on a stream of a server that did not answer")
}
