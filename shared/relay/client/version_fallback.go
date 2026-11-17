package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/coder/websocket"

	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// errV2AuthRejected marks a relay server that closed the connection on a v2
// auth without an answer. Relay servers before v0.82.0 accept only v1 and
// reject any other version that way.
var errV2AuthRejected = errors.New("relay server rejected the v2 auth")

const (
	// v1RetryHoldBase spaces the v2 tries to a relay server that rejected v2
	// twice in a row. The first reject allows a v2 try at the first drop.
	v1RetryHoldBase = 15 * time.Minute
	// v1RetryHoldMax caps the doubling of v1RetryHoldBase.
	v1RetryHoldMax = 2 * time.Hour
)

// v1Mark is a relay server that rejected the v2 auth and accepted v1.
type v1Mark struct {
	// rejects counts the v2 rejects since the last v2 connection.
	rejects int
	// retryAfter is the earliest wall clock time for the next v2 try.
	retryAfter time.Time
	// armed is set when a v1 connection dropped after the last reject. A drop
	// is when the server behind the URL may have been replaced.
	armed bool
}

// versionFallback remembers the relay servers that accept only the v1 auth, so
// later connects to them advertise v1 at once instead of failing on v2 first.
// After a v1 connection to such a server drops, the next connect tries v2 again,
// spaced by v1RetryHold when the server keeps rejecting it. Marks live as long
// as the manager.
type versionFallback struct {
	mu    sync.Mutex
	marks map[string]*v1Mark
	now   func() time.Time
}

func newVersionFallback() *versionFallback {
	return &versionFallback{marks: make(map[string]*v1Mark), now: wallNow}
}

// wallNow strips the monotonic reading, so the hold runs on while a phone sleeps.
func wallNow() time.Time {
	return time.Now().Round(0)
}

// v1RetryHold returns how long after the given count of consecutive v2 rejects
// the next v2 try waits.
func v1RetryHold(rejects int) time.Duration {
	if rejects < 2 {
		return 0
	}
	hold := v1RetryHoldBase
	for i := 2; i < rejects && hold < v1RetryHoldMax; i++ {
		hold *= 2
	}
	return min(hold, v1RetryHoldMax)
}

// maxVersion returns the highest protocol version to advertise to serverURL.
// A nil versionFallback remembers nothing.
func (f *versionFallback) maxVersion(serverURL string) messages.ProtocolVersion {
	if f == nil {
		return messages.CurrentProtocolVersion
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.marks[serverURL]
	if m == nil || (m.armed && !f.now().Before(m.retryAfter)) {
		return messages.CurrentProtocolVersion
	}
	return messages.ProtocolV1
}

// recordV1Only records a v2 reject by serverURL that a v1 auth then passed, so
// later connects to it advertise v1 until a v1 connection drops.
func (f *versionFallback) recordV1Only(serverURL string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.marks[serverURL]
	if m == nil {
		m = &v1Mark{}
		f.marks[serverURL] = m
	}
	m.rejects++
	m.armed = false
	m.retryAfter = f.now().Add(v1RetryHold(m.rejects))
}

// v1Dropped records that a v1 connection to serverURL dropped, so the next
// connect after the hold tries v2 again. Unmarked servers are left alone.
func (f *versionFallback) v1Dropped(serverURL string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.marks[serverURL]; m != nil {
		m.armed = true
	}
}

// recordV2 forgets the v1 mark of serverURL after it selected v2.
func (f *versionFallback) recordV2(serverURL string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.marks, serverURL)
}

// authRejectErr classifies a failed read of the auth response. A v2 auth the
// server answered by closing the connection becomes errV2AuthRejected. A
// timeout, a cancelled dial or a reset stays as it is, so a network failure
// does not move the server to v1.
func authRejectErr(ctx context.Context, advertised messages.ProtocolVersion, err error) error {
	if advertised < messages.ProtocolV2 || ctx.Err() != nil || !isServerClose(err) {
		return err
	}
	return fmt.Errorf("%w: %w", errV2AuthRejected, err)
}

// isServerClose reports whether err is an orderly close by the server: EOF on
// the WebSocket path, a QUIC close with code 0, or a WebSocket close frame.
func isServerClose(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, netErr.ErrClosedByServer) ||
		websocket.CloseStatus(err) != -1
}
