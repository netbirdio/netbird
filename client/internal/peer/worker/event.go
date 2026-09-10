package worker

import (
	"net"

	"github.com/pion/ice/v4"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/signaling"
)

// ICEStateChanged carries a Pion notification to the Conn event loop.
type ICEStateChanged struct {
	Agent *icemaker.ThreadSafeAgent
	State ice.ConnectionState
}

// ICECandidate carries a gathered candidate, or nil when gathering finishes.
type ICECandidate struct {
	Candidate ice.Candidate
}

// ICESelectedPair carries Pion's selected candidate pair notification.
type ICESelectedPair struct {
	Agent         *icemaker.ThreadSafeAgent
	Local, Remote ice.Candidate
}

// ICEDialDone transfers the dial result to the event loop. The producer closes
// Conn if posting fails; otherwise the consumer owns it, including on errors.
type ICEDialDone struct {
	Agent *icemaker.ThreadSafeAgent
	Conn  net.Conn
	Offer signaling.OfferAnswer
	Err   error
}
