package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// dropFromServer closes the client's relay connection on the server side and
// waits until the client has seen the drop.
func dropFromServer(t *testing.T, relay *oldRelay, c *Client) {
	t.Helper()
	relay.dropAll()
	require.Eventually(t, func() bool { return !c.Ready() }, 5*time.Second, 10*time.Millisecond, "the client must see the drop")
}

func TestV1DropRetriesV2(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeWS))
	addr := "127.0.0.1:50931"
	relay := &oldRelay{addr: addr}
	relay.start(t)
	url := "rel://" + addr
	vf := newVersionFallback()

	alice := connectAligned(t, url, vf, "alice")
	require.Equal(t, messages.ProtocolV1, alice.enc.Version(), "the old relay must put the client on v1")

	// The relay behind the URL is replaced by a current one, and the old
	// instance drops the connection on its way out.
	relay.upgraded.Store(true)
	dropFromServer(t, relay, alice)

	require.NoError(t, alice.Connect(context.Background()))
	assert.Equal(t, messages.ProtocolV2, alice.enc.Version(), "the reconnect after a v1 drop must try v2 and get it")
	assert.Equal(t, 60*time.Second, alice.alignedPeriod, "v2 brings the aligned heartbeat back")
	assert.Equal(t, int32(1), relay.rejected.Load(), "the upgraded relay must not reject")
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "a v2 connection must clear the v1 mark")
}

func TestV1DropRejectedFallsBackAtOnce(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeWS))
	addr := "127.0.0.1:50932"
	relay := &oldRelay{addr: addr}
	relay.start(t)
	url := "rel://" + addr
	vf := newVersionFallback()

	alice := connectAligned(t, url, vf, "alice")
	require.Equal(t, int32(1), relay.rejected.Load(), "first connect rejected once")

	// The relay is still old: the v2 try after the drop is rejected and the
	// same Connect falls back to v1.
	dropFromServer(t, relay, alice)
	require.NoError(t, alice.Connect(context.Background()), "the connect must succeed on v1 right after the v2 reject")
	assert.Equal(t, int32(2), relay.rejected.Load(), "the reconnect after a v1 drop must try v2 once")
	assert.Equal(t, messages.ProtocolV1, alice.enc.Version(), "the reconnect must end on v1")
	assert.Equal(t, messages.ProtocolV1, vf.maxVersion(url), "the relay must stay marked v1")
}

// fakeWallClock is a settable wall clock for the v1 retry hold.
type fakeWallClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeWallClock() *fakeWallClock {
	return &fakeWallClock{now: time.Date(2026, 11, 15, 15, 40, 0, 0, time.UTC)}
}

func (c *fakeWallClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeWallClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestRepeatedV2RejectsSpaceTries(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeWS))
	addr := "127.0.0.1:50933"
	relay := &oldRelay{addr: addr}
	relay.start(t)
	url := "rel://" + addr
	vf := newVersionFallback()
	clock := newFakeWallClock()
	vf.now = clock.Now

	alice := connectAligned(t, url, vf, "alice")
	require.Equal(t, int32(1), relay.rejected.Load(), "first connect rejected once")

	reconnect := func() {
		t.Helper()
		dropFromServer(t, relay, alice)
		require.NoError(t, alice.Connect(context.Background()))
		require.Equal(t, messages.ProtocolV1, alice.enc.Version(), "the old relay keeps the client on v1")
	}

	// The first drop after the first reject tries v2: the second reject.
	reconnect()
	require.Equal(t, int32(2), relay.rejected.Load(), "the first drop must try v2")

	// A flapping connection inside the hold must not try v2 on every reconnect.
	for i := 0; i < 5; i++ {
		clock.advance(time.Minute)
		reconnect()
	}
	assert.Equal(t, int32(2), relay.rejected.Load(), "reconnects inside the hold must stay on v1 without a v2 try")

	// After the hold the next reconnect tries v2 once, then the hold doubles.
	clock.advance(v1RetryHoldBase)
	reconnect()
	assert.Equal(t, int32(3), relay.rejected.Load(), "the first reconnect after the hold must try v2 once")

	clock.advance(v1RetryHoldBase)
	reconnect()
	assert.Equal(t, int32(3), relay.rejected.Load(), "the hold must double after the third reject")

	clock.advance(v1RetryHoldBase)
	reconnect()
	assert.Equal(t, int32(4), relay.rejected.Load(), "the reconnect after the doubled hold must try v2 once")
}

func TestV1RetryHold(t *testing.T) {
	tests := []struct {
		rejects int
		want    time.Duration
	}{
		{0, 0},
		{1, 0},
		{2, 15 * time.Minute},
		{3, 30 * time.Minute},
		{4, time.Hour},
		{5, 2 * time.Hour},
		{6, 2 * time.Hour},
		{1000, 2 * time.Hour},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, v1RetryHold(tt.rejects), "hold after %d rejects", tt.rejects)
	}
}

func TestVersionFallbackMarkLifecycle(t *testing.T) {
	const url = "rel://relay"
	vf := newVersionFallback()
	clock := newFakeWallClock()
	vf.now = clock.Now

	vf.v1Dropped(url)
	assert.Empty(t, vf.marks, "a drop must not mark an unmarked relay")
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "unmarked relay gets v2")

	vf.recordV1Only(url)
	assert.Equal(t, messages.ProtocolV1, vf.maxVersion(url), "marked relay gets v1")
	clock.advance(24 * time.Hour)
	assert.Equal(t, messages.ProtocolV1, vf.maxVersion(url), "time alone must not end the mark without a drop")

	vf.v1Dropped(url)
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "the first drop after the first reject allows v2")

	vf.recordV1Only(url)
	vf.v1Dropped(url)
	assert.Equal(t, messages.ProtocolV1, vf.maxVersion(url), "a drop inside the hold after the second reject keeps v1")
	clock.advance(v1RetryHoldBase - time.Second)
	assert.Equal(t, messages.ProtocolV1, vf.maxVersion(url), "v1 until the hold ends")
	clock.advance(time.Second)
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "an armed mark allows v2 once the hold ends")

	vf.recordV2(url)
	assert.Empty(t, vf.marks, "a v2 connection must remove the mark")
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "v2 after the mark is gone")

	// The reject count starts over after a v2 connection.
	vf.recordV1Only(url)
	vf.v1Dropped(url)
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "a fresh mark allows v2 at the first drop")
}

func TestV1CloseDoesNotArm(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeWS))
	addr := "127.0.0.1:50934"
	relay := &oldRelay{addr: addr}
	relay.start(t)
	url := "rel://" + addr
	vf := newVersionFallback()

	alice := connectAligned(t, url, vf, "alice")
	require.NoError(t, alice.Close())
	assert.Equal(t, messages.ProtocolV1, vf.maxVersion(url), "a local Close is no drop and must keep v1")
}
