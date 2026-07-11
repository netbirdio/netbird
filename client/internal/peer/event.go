package peer

import (
	"time"

	"github.com/pion/ice/v4"

	"github.com/netbirdio/netbird/route"
)

// event is a message processed by the Conn event loop. All mutable Conn state
// is owned by that loop; producers deliver events through the mailbox and
// never mutate Conn state directly.
type event any

// evClose asks the event loop to tear down the connection. done is closed
// once the teardown finished.
type evClose struct {
	signalToRemote bool
	done           chan struct{}
}

type evRemoteOffer struct {
	offer OfferAnswer
}

type evRemoteAnswer struct {
	answer OfferAnswer
}

type evRemoteCandidate struct {
	candidate ice.Candidate
	haRoutes  route.HAMap
}

type evICEReady struct {
	priority ConnPriority
	info     ICEConnInfo
}

type evICEDown struct {
	sessionChanged bool
}

type evRelayReady struct {
	info RelayConnInfo
}

type evRelayDown struct{}

// evRelayDialDone reports that the relay dial helper goroutine finished,
// successfully or not, so the loop may dispatch a pending offer.
type evRelayDialDone struct{}

type evWGTimeout struct{}

// evWGHandshake reports the first WireGuard handshake of the current watcher run.
type evWGHandshake struct {
	when time.Time
}

// evWGCheckOK reports a watcher check that observed a fresh handshake,
// including handshakes of connections that were already up.
type evWGCheckOK struct{}

// evGuardTick asks the loop to send a new offer to restore connectivity.
type evGuardTick struct{}
