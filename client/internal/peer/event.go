package peer

import (
	"context"
	"time"

	"github.com/pion/ice/v4"

	"github.com/netbirdio/netbird/client/internal/peer/signaling"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/route"
)

// event is a message processed by the Conn event loop. All mutable Conn state
// is owned by that loop; producers deliver events through the mailbox and
// never mutate Conn state directly.
type event any

// staleableEvent is implemented by events tied to the lifetime of a transport
// component (WG watcher, ICE agent, relay connection). Each such component runs
// under its own context, cancelled when the component is superseded; an event
// carrying a cancelled context is dropped at dispatch time. A cancel performed
// by an earlier event in the same drained batch already suppresses it.
type staleableEvent interface {
	isStale() bool
}

// evClose asks the event loop to tear down the connection. done is closed
// once the teardown finished.
type evClose struct {
	signalToRemote bool
	done           chan struct{}
}

type evRemoteOffer struct {
	offer signaling.OfferAnswer
}

type evRemoteAnswer struct {
	answer signaling.OfferAnswer
}

type evRemoteCandidate struct {
	candidate ice.Candidate
	haRoutes  route.HAMap
}

type evICEReady struct {
	priority worker.ConnPriority
	info     worker.ICEConnInfo
}

type evICEDown struct {
	sessionChanged bool
}

type evRelayReady struct {
	info worker.RelayConnInfo
}

type evRelayDown struct{}

// evRelayDialDone reports that the relay dial helper goroutine finished,
// successfully or not, so the loop may dispatch a pending offer.
type evRelayDialDone struct{}

type evWGTimeout struct {
	ctx context.Context
}

func (e evWGTimeout) isStale() bool { return e.ctx.Err() != nil }

// evWGHandshake reports the first WireGuard handshake of the current watcher run.
type evWGHandshake struct {
	when time.Time
}

// evWGCheckOK reports a watcher check that observed a fresh handshake,
// including handshakes of connections that were already up.
type evWGCheckOK struct{}

// evGuardTick asks the loop to send a new offer to restore connectivity.
type evGuardTick struct{}
