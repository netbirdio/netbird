package peer

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

func TestWorkerICE_RemoteRestartPreservesAdvertisedSession(t *testing.T) {
	w := newTestWorkerICE(t)
	t.Cleanup(w.Close)
	w.dialFunc = parkDial
	advertised := w.SessionID()
	remoteSession := ICESessionID("remote-first")
	offer := OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "remoteufrag", Pwd: "remote-password-long-enough"},
		SessionID:      &remoteSession,
	}
	w.OnNewOffer(&offer)
	require.True(t, w.InProgress(), "the first remote session must start ICE")
	w.muxAgent.Lock()
	firstAgent := w.agent
	w.muxAgent.Unlock()

	// The same callback handles answers. A changed remote ID must not create
	// an unannounced local ID that makes the remote restart on our next offer.
	secondSession := ICESessionID("remote-restarted")
	answer := offer
	answer.SessionID = &secondSession
	w.OnNewOffer(&answer)
	assert.Equal(t, advertised, w.SessionID(), "following a remote restart must keep our advertised ID")
	w.muxAgent.Lock()
	secondAgent := w.agent
	w.muxAgent.Unlock()
	assert.NotSame(t, firstAgent, secondAgent, "the changed remote session must still rebuild ICE")

	w.OnNewOffer(&answer)
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	assert.Same(t, secondAgent, w.agent, "a repeated answer must keep the replacement agent")
}

func TestWorkerICE_LocalCloseChangesAdvertisedSession(t *testing.T) {
	w := newTestWorkerICE(t)
	dialStarted := make(chan struct{})
	dialDone := make(chan struct{})
	w.dialFunc = func(ctx context.Context, _ *icemaker.ThreadSafeAgent, _ *OfferAnswer) (net.Conn, error) {
		close(dialStarted)
		defer close(dialDone)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	session := ICESessionID("remote-session")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "remoteufrag", Pwd: "remote-password-long-enough"},
		SessionID:      &session,
	})
	<-dialStarted
	advertised := w.SessionID()
	w.Close()
	assert.NotEqual(t, advertised, w.SessionID(), "a local teardown must tell the remote to restart")
	closedSession := w.SessionID()

	// The abandoned dial goroutine cleans up after Close returned.
	<-dialDone
	assert.Never(t, func() bool { return w.SessionID() != closedSession }, 200*time.Millisecond, 10*time.Millisecond,
		"the late cleanup of a closed negotiation must not restart again")
	w.Close()
	assert.Equal(t, closedSession, w.SessionID(), "closing an idle worker must not restart again")
}

// parkDial stands in for the ICE dial. It never connects and returns once the
// negotiation is abandoned, so a test decides when a negotiation fails.
func parkDial(ctx context.Context, _ *icemaker.ThreadSafeAgent, _ *OfferAnswer) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func newTestSessionID(t *testing.T) ICESessionID {
	t.Helper()
	sid, err := NewICESessionID()
	require.NoError(t, err)
	return sid
}

// handshakeSide is one end of a simulated signaling exchange.
type handshakeSide interface {
	// message builds the offer or answer the side would send now.
	message() OfferAnswer
	// receive hands a remote offer or answer to the side's ICE logic.
	receive(msg OfferAnswer)
	// teardowns counts negotiations the side tore down to follow a remote restart.
	teardowns() int
	// failAgent ends the side's current negotiation as an ICE failure does.
	failAgent()
}

// workerSide drives a real WorkerICE.
type workerSide struct {
	t        *testing.T
	w        *WorkerICE
	replaced int
}

func newWorkerSide(t *testing.T) *workerSide {
	t.Helper()
	w := newTestWorkerICE(t)
	w.dialFunc = parkDial
	t.Cleanup(w.Close)
	return &workerSide{t: t, w: w}
}

func (s *workerSide) message() OfferAnswer {
	sid := s.w.SessionID()
	ufrag, pwd := s.w.GetLocalUserCredentials()
	return OfferAnswer{IceCredentials: IceCredentials{UFrag: ufrag, Pwd: pwd}, SessionID: &sid}
}

func (s *workerSide) receive(msg OfferAnswer) {
	before := s.agent()
	s.w.OnNewOffer(&msg)
	if after := s.agent(); before != nil && after != before {
		s.replaced++
	}
}

func (s *workerSide) teardowns() int { return s.replaced }

func (s *workerSide) agent() *icemaker.ThreadSafeAgent {
	s.w.muxAgent.Lock()
	defer s.w.muxAgent.Unlock()
	return s.w.agent
}

// failAgent runs the cleanup the dial goroutine or the Failed state callback
// performs when the current negotiation dies.
func (s *workerSide) failAgent() {
	s.t.Helper()
	s.w.muxAgent.Lock()
	agent, cancel := s.w.agent, s.w.agentDialerCancel
	s.w.muxAgent.Unlock()
	require.NotNil(s.t, agent, "failing requires a running negotiation")
	s.w.closeAgent(agent, cancel)
}

// legacySide models a remote peer running a release from before this change:
// when it follows a remote restart it also picks a new session ID of its own,
// which it announces only with its next offer or answer.
type legacySide struct {
	t         *testing.T
	sessionID ICESessionID
	remoteID  ICESessionID
	hasAgent  bool
	replaced  int
}

func newLegacySide(t *testing.T) *legacySide {
	return &legacySide{t: t, sessionID: newTestSessionID(t)}
}

func (s *legacySide) message() OfferAnswer {
	sid := s.sessionID
	return OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "legacyufrag", Pwd: "legacy-password-long-enough"},
		SessionID:      &sid,
	}
}

func (s *legacySide) receive(msg OfferAnswer) {
	if msg.SessionID == nil {
		s.hasAgent = true
		return
	}
	if s.hasAgent {
		if *msg.SessionID == s.remoteID {
			return
		}
		s.replaced++
		s.sessionID = newTestSessionID(s.t)
	}
	s.hasAgent = true
	s.remoteID = *msg.SessionID
}

func (s *legacySide) teardowns() int { return s.replaced }

func (s *legacySide) failAgent() {
	s.hasAgent = false
	s.remoteID = ""
	s.sessionID = newTestSessionID(s.t)
}

// exchange runs one guard-driven round in the order Handshaker.Listen uses: the
// answerer handles the offer and answers with the session ID it holds
// afterwards, and the offerer handles the answer without replying.
func exchange(offerer, answerer handshakeSide) {
	answerer.receive(offerer.message())
	offerer.receive(answerer.message())
}

// offerPattern decides which side's guard sends the offer in a round.
type offerPattern struct {
	name   string
	picker func(round int, local, remote handshakeSide) (offerer, answerer handshakeSide)
}

var offerPatterns = []offerPattern{
	{
		// A routing peer whose relay is down keeps offering on its own.
		name: "local peer offers",
		picker: func(_ int, local, remote handshakeSide) (handshakeSide, handshakeSide) {
			return local, remote
		},
	},
	{
		name: "both peers offer",
		picker: func(round int, local, remote handshakeSide) (handshakeSide, handshakeSide) {
			if round%2 == 0 {
				return local, remote
			}
			return remote, local
		},
	},
}

// assertSettles runs guard rounds and requires the pair to stop restarting
// each other: at most maxTeardowns in total, and none once half the rounds ran.
func assertSettles(t *testing.T, pattern offerPattern, local, remote handshakeSide, maxTeardowns int) {
	t.Helper()
	const rounds = 10

	total := func() int { return local.teardowns() + remote.teardowns() }
	start := total()
	var halfway int
	for round := range rounds {
		if round == rounds/2 {
			halfway = total()
		}
		offerer, answerer := pattern.picker(round, local, remote)
		exchange(offerer, answerer)
	}

	assert.LessOrEqual(t, total()-start, maxTeardowns, "the peers must not keep restarting each other")
	assert.Equal(t, halfway, total(), "the negotiation must be stable in the later rounds")
}

// establish runs the first offer and answer, so both sides negotiate.
func establish(t *testing.T, local, remote handshakeSide) {
	t.Helper()
	exchange(local, remote)
	require.Zero(t, local.teardowns()+remote.teardowns(), "the first exchange must not restart anything")
}

func TestICESession_SettlesAfterAgentFailure(t *testing.T) {
	sides := []struct {
		name   string
		remote func(t *testing.T) handshakeSide
	}{
		{name: "current remote", remote: func(t *testing.T) handshakeSide { return newWorkerSide(t) }},
		{name: "legacy remote", remote: func(t *testing.T) handshakeSide { return newLegacySide(t) }},
	}
	failures := []struct {
		name string
		fail func(local, remote handshakeSide)
	}{
		{name: "remote agent fails", fail: func(_, remote handshakeSide) { remote.failAgent() }},
		{name: "local agent fails", fail: func(local, _ handshakeSide) { local.failAgent() }},
		{name: "both agents fail", fail: func(local, remote handshakeSide) {
			local.failAgent()
			remote.failAgent()
		}},
	}

	for _, side := range sides {
		for _, failure := range failures {
			for _, pattern := range offerPatterns {
				t.Run(fmt.Sprintf("%s/%s/%s", side.name, failure.name, pattern.name), func(t *testing.T) {
					local := newWorkerSide(t)
					remote := side.remote(t)
					establish(t, local, remote)

					failure.fail(local, remote)
					assertSettles(t, pattern, local, remote, 2)
				})
			}
		}
	}
}

// TestICESession_LocalCloseRestartsRemote covers an explicit teardown, as on a
// WireGuard handshake timeout. The remote must start over as well, or it keeps
// answering from the negotiation this side just abandoned.
func TestICESession_LocalCloseRestartsRemote(t *testing.T) {
	for _, pattern := range offerPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			local := newWorkerSide(t)
			remote := newWorkerSide(t)
			establish(t, local, remote)

			local.w.Close()
			assertSettles(t, pattern, local, remote, 1)
			assert.Equal(t, 1, remote.teardowns(), "the remote must restart its negotiation exactly once")
		})
	}
}

func TestICESession_DuplicateMessagesKeepNegotiation(t *testing.T) {
	local := newWorkerSide(t)
	remote := newWorkerSide(t)

	offer := local.message()
	remote.receive(offer)
	answer := remote.message()
	local.receive(answer)

	// Signaling may deliver the same message again, and a peer answers every
	// offer, including repeats of one it already handled.
	remote.receive(offer)
	local.receive(answer)
	local.receive(remote.message())

	assert.Zero(t, local.teardowns(), "a repeated answer must not restart the negotiation")
	assert.Zero(t, remote.teardowns(), "a repeated offer must not restart the negotiation")
}

// TestICESession_RemoteWithoutSessionIDKeepsNegotiation covers remote peers
// too old to send session IDs: once negotiating, their messages cannot tell a
// restart from a repeat, so they must not tear anything down.
func TestICESession_RemoteWithoutSessionIDKeepsNegotiation(t *testing.T) {
	local := newWorkerSide(t)
	unversioned := OfferAnswer{IceCredentials: IceCredentials{UFrag: "oldufrag", Pwd: "old-password-long-enough"}}

	local.receive(unversioned)
	require.NotNil(t, local.agent(), "a message without a session ID must still start ICE")
	advertised := local.w.SessionID()

	for range 3 {
		local.receive(unversioned)
	}
	assert.Zero(t, local.teardowns(), "messages without a session ID must not restart the negotiation")
	assert.Equal(t, advertised, local.w.SessionID(), "the advertised session must not change")
}

// TestWorkerICE_StaleCleanupKeepsAdvertisedSession covers the cleanup of a
// replaced negotiation finishing late, from its dial goroutine or its Closed
// state callback. It must neither pick a new session ID, an unannounced local
// restart, nor disturb the negotiation that replaced it.
func TestWorkerICE_StaleCleanupKeepsAdvertisedSession(t *testing.T) {
	local := newWorkerSide(t)
	remote := newWorkerSide(t)
	establish(t, local, remote)

	local.w.muxAgent.Lock()
	oldAgent, oldCancel := local.w.agent, local.w.agentDialerCancel
	local.w.muxAgent.Unlock()

	remote.failAgent()
	exchange(local, remote)
	require.Equal(t, 1, local.teardowns(), "the local side must follow the remote restart")
	advertised := local.w.SessionID()
	current := local.agent()

	local.w.closeAgent(oldAgent, oldCancel)

	assert.Equal(t, advertised, local.w.SessionID(), "a stale cleanup must not change the advertised session")
	assert.Same(t, current, local.agent(), "a stale cleanup must keep the current negotiation")
	assertSettles(t, offerPatterns[1], local, remote, 0)
}
