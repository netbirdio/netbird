// Package approval brokers per-attempt user-accept prompts for inbound
// remote access (VNC today, SSH and others in the future). A caller pushes
// a Prompt; the broker emits a SystemEvent on the daemon→UI stream and
// blocks until the UI calls the daemon's RespondApproval RPC, the per-
// request timeout fires, or no subscriber is connected. The latter case
// fails closed so a backgrounded UI cannot silently bypass the gate.
package approval

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// Metadata keys the broker reserves on the emitted SystemEvent. Callers
// should not set these themselves; values in Prompt.Metadata that collide
// are overwritten by the broker.
const (
	MetaRequestID = "request_id"
	MetaKind      = "kind"
	MetaExpiresAt = "expires_at"
)

// ShortKeyFingerprint formats a hex-encoded Noise_IK static pubkey as a
// short, eyeball-able fingerprint to display in the approval dialog.
// The dashboard-supplied display name attached to a SessionPubKey isn't
// cryptographically asserted by the connecting client, so the prompt
// must also show something that IS: the key fingerprint, a hash of
// the static public key the client just proved possession of during the
// Noise handshake. Returns the empty string when the input is too short
// to plausibly be a hex pubkey, so the row is omitted rather than
// rendered as a misleading partial.
//
// Output format: 16 hex chars grouped as XXXX-XXXX-XXXX-XXXX (64 bits of
// fingerprint, resistant to random-prefix collisions and easy for a human
// to compare with an out-of-band reference).
func ShortKeyFingerprint(hexKey string) string {
	if len(hexKey) < 8 {
		return ""
	}
	src := hexKey
	if len(src) > 16 {
		src = src[:16]
	}
	var out []byte
	for i, c := range src {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// Kind values for the well-known prompt subjects. New subsystems should
// add a constant here so the UI can dispatch on a known string.
const (
	KindVNC = "vnc"
	KindSSH = "ssh"
)

// DefaultTimeout is the wall-clock window the user has to accept or deny a
// pending approval before the broker fails closed and returns ErrTimeout.
//
// The connection spends this whole window in silence: the gate runs before the
// protocol handshake, so nothing reaches the client until the user answers. A
// client therefore has to tolerate a quiet connection for longer than this, or
// it gives up before the answer arrives.
//
// A minute is what a prompt on a phone needs: it arrives as a notification on
// a device that is in a pocket, and answering it means noticing it, unlocking,
// and working through the system's screen-capture dialog. A desktop dialog
// appears on the screen the user is already looking at and rarely uses more
// than a few seconds of it.
const DefaultTimeout = 60 * time.Second

// timeoutValue returns the active timeout. It's a var so tests in this
// package can shorten the wait without exposing a setter on the public
// API. Production code always sees DefaultTimeout.
var timeoutValue = func() time.Duration { return DefaultTimeout }

// ErrNoSubscriber indicates no UI is connected to consume the prompt.
// The caller must reject the underlying connection (fail-closed).
var ErrNoSubscriber = errors.New("no UI subscriber connected for approval")

// ErrPromptNotShown indicates a UI is connected but never received the prompt,
// because its event queue was full when the prompt was published. Distinct from
// ErrNoSubscriber so an operator can tell "nobody was listening" from "somebody
// was listening and we could not reach them", which have different remedies.
// Fail-closed either way.
var ErrPromptNotShown = errors.New("approval prompt was not delivered to the UI")

// ErrTimeout indicates the user did not respond within DefaultTimeout.
var ErrTimeout = errors.New("approval timed out")

// ErrDenied indicates the user explicitly denied the connection.
var ErrDenied = errors.New("approval denied")

// EventPublisher is the subset of peer.Status used to emit prompts.
type EventPublisher interface {
	// PublishEvent reports whether the event reached at least one live
	// subscriber. A prompt nobody received is one nobody can answer.
	PublishEvent(
		severity proto.SystemEvent_Severity,
		category proto.SystemEvent_Category,
		msg string,
		userMsg string,
		metadata map[string]string,
	) bool
	HasEventSubscribers() bool
}

// Prompt describes the pending request shown to the user. Kind selects
// the UI dispatch path (e.g. "vnc", "ssh"). Subject is the human-readable
// one-liner the UI may show as a title or notification body. Metadata is
// passed through verbatim and is the subsystem-specific payload (peer
// name, source IP, mode, etc.).
type Prompt struct {
	Kind     string
	Subject  string
	Metadata map[string]string
}

// Decision carries the user's response to an approval prompt. ViewOnly is
// only meaningful when Accept is true; it lets the host grant the
// connection but signal the requester that input control is withheld.
type Decision struct {
	Accept   bool
	ViewOnly bool
}

// pendingRequest is one in-flight prompt. resolved records that somebody has
// already claimed it, so the user's decision and the caller giving up race for
// the same entry under Broker.mu and exactly one of them wins.
type pendingRequest struct {
	resp     chan Decision
	resolved bool
}

// Broker holds in-flight approval requests keyed by request ID.
type Broker struct {
	pub EventPublisher

	mu      sync.Mutex
	pending map[string]*pendingRequest
}

// New returns a broker that publishes prompts via pub.
func New(pub EventPublisher) *Broker {
	return &Broker{
		pub:     pub,
		pending: make(map[string]*pendingRequest),
	}
}

// Request emits a SystemEvent for p and blocks until the UI calls Respond,
// ctx is cancelled, or DefaultTimeout elapses. Returns a Decision when
// the user replied; ErrDenied / ErrTimeout / ErrNoSubscriber / ctx.Err
// otherwise. Callers must treat any non-nil error as a deny.
func (b *Broker) Request(ctx context.Context, p Prompt) (Decision, error) {
	var zero Decision
	if b == nil || b.pub == nil {
		return zero, fmt.Errorf("approval broker not configured")
	}
	if !b.pub.HasEventSubscribers() {
		return zero, ErrNoSubscriber
	}

	id := uuid.NewString()
	resp := make(chan Decision, 1)

	b.mu.Lock()
	b.pending[id] = &pendingRequest{resp: resp}
	b.mu.Unlock()

	defer b.dropPending(id)

	timeout := timeoutValue()
	expiresAt := time.Now().Add(timeout)
	meta := make(map[string]string, len(p.Metadata)+3)
	for k, v := range p.Metadata {
		meta[k] = v
	}
	meta[MetaRequestID] = id
	meta[MetaKind] = p.Kind
	meta[MetaExpiresAt] = expiresAt.UTC().Format(time.RFC3339)

	subject := p.Subject
	if subject == "" {
		subject = fmt.Sprintf("%s connection requires approval", p.Kind)
	}
	// A subscriber whose queue is full drops the event silently. Waiting out the
	// timeout for a prompt that never appeared spends the caller's whole
	// approval window before denying, and tells the user it timed out rather
	// than that nothing ever asked them.
	if !b.pub.PublishEvent(proto.SystemEvent_INFO, proto.SystemEvent_APPROVAL, subject, subject, meta) {
		log.Warnf("approval request %s (%s) reached no subscriber; denying without waiting", id, p.Kind)
		return zero, ErrPromptNotShown
	}
	log.Debugf("approval request %s (%s) emitted: %s", id, p.Kind, subject)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case d := <-resp:
		return decisionResult(d)
	case <-timer.C:
		if d, answered := b.giveUp(id, resp); answered {
			return decisionResult(d)
		}
		return zero, ErrTimeout
	case <-ctx.Done():
		if d, answered := b.giveUp(id, resp); answered {
			return decisionResult(d)
		}
		return zero, ctx.Err()
	}
}

// giveUp abandons the request and reports whether the user's decision landed
// first, in which case it is returned and must be honoured.
//
// Respond and this path claim the same entry under the same lock, so exactly
// one of them wins. Without that claim, a click arriving as the timer fires
// would be told it matched a live prompt while this caller had already denied
// the connection: the user would see their accept confirmed and the session
// dropped anyway.
func (b *Broker) giveUp(id string, resp <-chan Decision) (Decision, bool) {
	if b.claim(id) {
		return Decision{}, false
	}
	// Respond claimed the entry and sent while still holding the lock, so the
	// decision is already buffered and this receive cannot block.
	return <-resp, true
}

// claim marks the request resolved so nothing else can take it, reporting
// whether the caller got there first. Callers must not already hold b.mu.
func (b *Broker) claim(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	p, ok := b.pending[id]
	if !ok || p.resolved {
		return false
	}
	p.resolved = true
	delete(b.pending, id)
	return true
}

// decisionResult maps a decision the user actually made onto the Request
// contract: a deny is an error, an accept carries the view-only flag back.
func decisionResult(d Decision) (Decision, error) {
	if !d.Accept {
		return Decision{}, ErrDenied
	}
	return d, nil
}

// Respond delivers the user's decision for id. Returns true when a pending
// request matched and was woken, false when id was unknown or already done.
func (b *Broker) Respond(id string, d Decision) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	p, ok := b.pending[id]
	if !ok || p.resolved {
		return false
	}
	p.resolved = true
	delete(b.pending, id)
	// The channel is buffered and claimed exactly once, so this never blocks.
	// Sent under the lock so a Request that loses the claim race finds the
	// decision already waiting instead of racing this send.
	p.resp <- d
	return true
}

func (b *Broker) dropPending(id string) {
	b.mu.Lock()
	delete(b.pending, id)
	b.mu.Unlock()
}
