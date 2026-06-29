package approval

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

// fakePublisher records published events and reports whether subscribers
// are connected. The subscribers flag is the security-critical signal:
// when false the broker must refuse to emit and the gate must fail closed.
type fakePublisher struct {
	mu          sync.Mutex
	subscribers bool
	events      []*proto.SystemEvent
}

func (p *fakePublisher) PublishEvent(
	severity proto.SystemEvent_Severity,
	category proto.SystemEvent_Category,
	msg string,
	userMsg string,
	metadata map[string]string,
) {
	p.mu.Lock()
	p.events = append(p.events, &proto.SystemEvent{
		Severity:    severity,
		Category:    category,
		Message:     msg,
		UserMessage: userMsg,
		Metadata:    metadata,
	})
	p.mu.Unlock()
}

func (p *fakePublisher) HasEventSubscribers() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.subscribers
}

func (p *fakePublisher) lastEvent(t *testing.T) *proto.SystemEvent {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	require.NotEmpty(t, p.events, "publisher saw no events")
	return p.events[len(p.events)-1]
}

func (p *fakePublisher) eventCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

// TestRequestNoSubscriberFailsClosed is the core fail-closed invariant:
// when the UI is not subscribed, the broker must refuse without emitting
// an event or arming a waiter. A regression here is a silent bypass.
func TestRequestNoSubscriberFailsClosed(t *testing.T) {
	pub := &fakePublisher{subscribers: false}
	b := New(pub)

	_, err := b.Request(context.Background(), Prompt{Kind: KindVNC, Subject: "test"})
	assert.ErrorIs(t, err, ErrNoSubscriber)
	assert.Equal(t, 0, pub.eventCount(), "no event must be emitted when fail-closed")

	b.mu.Lock()
	pending := len(b.pending)
	b.mu.Unlock()
	assert.Equal(t, 0, pending, "no waiter must be registered on fail-closed")
}

// TestRequestTimeoutDenies verifies that a request without a UI response
// returns ErrTimeout (deny) rather than nil (silent accept). Uses a short
// per-test broker timeout via Respond after the fact to keep the test fast.
func TestRequestTimeoutDenies(t *testing.T) {
	// Replace DefaultTimeout for the lifetime of this test.
	orig := DefaultTimeout
	defaultTimeout(t, 60*time.Millisecond)
	defer defaultTimeout(t, orig)

	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	start := time.Now()
	_, err := b.Request(context.Background(), Prompt{Kind: KindVNC, Subject: "test"})
	assert.ErrorIs(t, err, ErrTimeout, "missing user response must yield ErrTimeout, not nil")
	assert.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond, "timeout fired prematurely")
}

// TestRequestDenied returns ErrDenied when the UI responds with false.
func TestRequestDenied(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	var requestID string
	done := make(chan error, 1)
	go func() {
		done <- requestErr(b, context.Background(), Prompt{Kind: KindVNC, Subject: "test"})
	}()

	requestID = waitForRequestID(t, pub)
	require.True(t, b.Respond(requestID, Decision{Accept: false}))

	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrDenied)
	case <-time.After(time.Second):
		t.Fatal("Request did not return after Respond(false)")
	}
}

// TestRequestAccepted is the happy path. Failure here doesn't bypass the
// gate but breaks the feature.
func TestRequestAccepted(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	done := make(chan error, 1)
	go func() {
		done <- requestErr(b, context.Background(), Prompt{Kind: KindVNC, Subject: "test"})
	}()

	id := waitForRequestID(t, pub)
	require.True(t, b.Respond(id, Decision{Accept: true}))

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Request did not return after Respond(true)")
	}
}

// TestRequestCtxCancelDenies verifies that an upstream cancel (e.g. the
// engine shutting down mid-prompt) returns the cancel error rather than
// nil. A nil here would be a silent bypass on shutdown races.
func TestRequestCtxCancelDenies(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- requestErr(b, ctx, Prompt{Kind: KindVNC, Subject: "test"})
	}()

	// Wait until the prompt is in flight so cancel races a live waiter.
	_ = waitForRequestID(t, pub)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Request did not return after ctx cancel")
	}
}

// TestRespondUnknownIsNoop ensures a stray RespondApproval RPC cannot
// affect or accidentally accept any in-flight request whose id it doesn't
// match. Also confirms it doesn't panic.
func TestRespondUnknownIsNoop(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	// No in-flight prompts: Respond returns false.
	assert.False(t, b.Respond("does-not-exist", Decision{Accept: true}))

	// With an in-flight prompt, a wrong id still returns false and the
	// prompt remains armed (eventually timing out as a deny).
	defaultTimeout(t, 60*time.Millisecond)
	defer defaultTimeout(t, DefaultTimeout)

	done := make(chan error, 1)
	go func() {
		done <- requestErr(b, context.Background(), Prompt{Kind: KindVNC})
	}()
	realID := waitForRequestID(t, pub)
	assert.False(t, b.Respond("totally-bogus", Decision{Accept: true}), "unknown id must not match")
	assert.NotEqual(t, "totally-bogus", realID)

	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrTimeout, "armed prompt must still time out, not accept")
	case <-time.After(time.Second):
		t.Fatal("prompt did not resolve")
	}
}

// TestRespondAfterTimeoutNoop confirms a late accept response can't
// retroactively flip a denied (timed-out) request. The dropPending defer
// in Request must have removed the entry by the time Respond races in.
func TestRespondAfterTimeoutNoop(t *testing.T) {
	defaultTimeout(t, 30*time.Millisecond)
	defer defaultTimeout(t, DefaultTimeout)

	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	done := make(chan error, 1)
	go func() {
		done <- requestErr(b, context.Background(), Prompt{Kind: KindVNC})
	}()
	id := waitForRequestID(t, pub)

	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrTimeout)
	case <-time.After(time.Second):
		t.Fatal("prompt did not time out")
	}

	assert.False(t, b.Respond(id, Decision{Accept: true}), "late respond must be no-op")
}

// TestRespondDoubleNoop ensures a duplicate ack from the UI doesn't leak
// past the matched waiter or panic on a closed/full channel.
func TestRespondDoubleNoop(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	done := make(chan error, 1)
	go func() {
		done <- requestErr(b, context.Background(), Prompt{Kind: KindVNC})
	}()
	id := waitForRequestID(t, pub)
	require.True(t, b.Respond(id, Decision{Accept: true}))
	assert.False(t, b.Respond(id, Decision{Accept: false}), "second response must be no-op")

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("prompt did not resolve")
	}
}

// TestNilBrokerRequestErrors guards the engine pre-init path where the
// broker may not yet exist (or its publisher is nil): Request must
// error, never silently accept.
func TestNilBrokerRequestErrors(t *testing.T) {
	var b *Broker
	_, err := b.Request(context.Background(), Prompt{Kind: KindVNC})
	assert.Error(t, err, "nil broker must error, never silently accept")

	b2 := New(nil)
	_, err = b2.Request(context.Background(), Prompt{Kind: KindVNC})
	assert.Error(t, err, "broker with nil publisher must error, never silently accept")
}

// TestPromptMetadataInjected confirms the broker stamps request_id, kind,
// and expires_at on the emitted event. The UI relies on these keys; if
// they are dropped, the user cannot route the prompt and the response
// path breaks (which fails closed via timeout).
func TestPromptMetadataInjected(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	done := make(chan error, 1)
	go func() {
		done <- requestErr(b, context.Background(), Prompt{
			Kind:     KindVNC,
			Subject:  "VNC connection from peerA",
			Metadata: map[string]string{"peer_name": "peerA"},
		})
	}()

	id := waitForRequestID(t, pub)
	ev := pub.lastEvent(t)

	assert.Equal(t, proto.SystemEvent_APPROVAL, ev.Category)
	assert.Equal(t, KindVNC, ev.Metadata[MetaKind])
	assert.Equal(t, id, ev.Metadata[MetaRequestID])
	assert.NotEmpty(t, ev.Metadata[MetaExpiresAt])
	assert.Equal(t, "peerA", ev.Metadata["peer_name"], "caller metadata must pass through")

	require.True(t, b.Respond(id, Decision{Accept: true}))
	<-done
}

// TestConcurrentRequests verifies that two concurrent prompts are tracked
// independently. A bug that aliases ids would let one Respond unblock
// the wrong waiter (a silent accept across prompts).
func TestConcurrentRequests(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	const n = 20
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			results <- requestErr(b, context.Background(), Prompt{Kind: KindVNC})
		}()
	}

	ids := waitForNRequestIDs(t, pub, n)
	require.Len(t, ids, n)

	// Deny exactly half, accept the rest. Track outcome per id so we can
	// match each Request's return value against the response we sent.
	denySet := make(map[string]bool, n)
	for i, id := range ids {
		deny := i%2 == 0
		denySet[id] = deny
		require.True(t, b.Respond(id, Decision{Accept: !deny}))
	}

	// Collect all returns and check no nil errors slipped past a deny.
	var accepted, denied atomic.Int32
	for i := 0; i < n; i++ {
		select {
		case err := <-results:
			if err == nil {
				accepted.Add(1)
			} else {
				assert.ErrorIs(t, err, ErrDenied)
				denied.Add(1)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("only got %d/%d responses", i, n)
		}
	}
	assert.Equal(t, int32(n/2), denied.Load())
	assert.Equal(t, int32(n/2), accepted.Load())
}

// waitForRequestID blocks until the publisher sees its next event and
// returns the request_id stamped on it.
func waitForRequestID(t *testing.T, pub *fakePublisher) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pub.mu.Lock()
		count := len(pub.events)
		var id string
		if count > 0 {
			id = pub.events[count-1].Metadata[MetaRequestID]
		}
		pub.mu.Unlock()
		if id != "" {
			return id
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timeout waiting for emitted event")
	return ""
}

func waitForNRequestIDs(t *testing.T, pub *fakePublisher, n int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pub.mu.Lock()
		count := len(pub.events)
		pub.mu.Unlock()
		if count >= n {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	out := make([]string, 0, len(pub.events))
	seen := make(map[string]struct{}, len(pub.events))
	for _, ev := range pub.events {
		id := ev.Metadata[MetaRequestID]
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) < n {
		t.Fatalf("only got %d/%d request ids", len(out), n)
	}
	return out
}

// defaultTimeout swaps the broker's per-request wall-clock window so the
// timeout tests run quickly. Restores the prior value on the next call.
func defaultTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	if d <= 0 {
		t.Fatal("defaultTimeout must be > 0")
	}
	timeoutValue = func() time.Duration { return d }
}

// requestErr wraps Broker.Request to drop the Decision when tests only
// care about the error path. Keeps the goroutine bodies tight.
func requestErr(b *Broker, ctx context.Context, p Prompt) error {
	_, err := b.Request(ctx, p)
	return err
}

// TestRequestViewOnly checks the view-only outcome flows through Request's
// Decision return without being silently swallowed.
func TestRequestViewOnly(t *testing.T) {
	pub := &fakePublisher{subscribers: true}
	b := New(pub)

	type result struct {
		d   Decision
		err error
	}
	done := make(chan result, 1)
	go func() {
		d, err := b.Request(context.Background(), Prompt{Kind: KindVNC})
		done <- result{d, err}
	}()

	id := waitForRequestID(t, pub)
	require.True(t, b.Respond(id, Decision{Accept: true, ViewOnly: true}))

	select {
	case r := <-done:
		assert.NoError(t, r.err)
		assert.True(t, r.d.Accept)
		assert.True(t, r.d.ViewOnly, "ViewOnly must survive the round-trip")
	case <-time.After(time.Second):
		t.Fatal("view-only request did not resolve")
	}
}
