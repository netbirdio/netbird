package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/metrics"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/store"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasectl"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	bufferSize = messages.MaxMessageSize

	errCloseConn = "failed to close connection to peer: %s"
)

// Peer represents a peer connection
type Peer struct {
	metrics  *metrics.Metrics
	log      *log.Entry
	id       messages.PeerID
	version  messages.ProtocolVersion
	enc      messages.Encoder
	conn     listener.Conn
	connMu   sync.RWMutex
	store    *store.Store
	notifier *store.PeerNotifier

	ctx       context.Context
	ctxCancel context.CancelFunc

	peersListener *store.Listener

	// phase is the aligned heartbeat schedule, stock until a verified signed
	// phase arrives.
	phase *phasectl.Phase
	// phaseVerifier checks signed phases that arrive after the handshake.
	phaseVerifier *phasesig.Verifier
	// periodLimits clamp the period of signed phases before they are verified.
	periodLimits alignedhb.PeriodLimits
	// transportPeriod is the heartbeat period the transport was tuned for, zero
	// while it is stock. Only the Work goroutine uses it after the handshake.
	transportPeriod time.Duration

	// between the online peer collection step and the notification sending should not be sent offline notifications from another thread
	notificationMutex sync.Mutex
}

// NewPeer creates a new Peer instance and prepare custom logging
func NewPeer(metrics *metrics.Metrics, id messages.PeerID, version messages.ProtocolVersion, conn listener.Conn, store *store.Store, notifier *store.PeerNotifier) *Peer {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Peer{
		metrics:   metrics,
		log:       log.WithField("peer_id", id.String()),
		id:        id,
		version:   version,
		enc:       messages.NewEncoder(version, conn.MaxMessageSize()),
		conn:      conn,
		store:     store,
		notifier:  notifier,
		ctx:       ctx,
		ctxCancel: cancel,
	}
	p.phase = phasectl.New("relay", id.String(), p.hbMetrics(), p.log)

	return p
}

// Work reads data from the connection
// It manages the protocol (healthcheck, transport, close). Read the message and determine the message type and handle
// the message accordingly.
func (p *Peer) Work() {
	p.peersListener = p.notifier.NewListener(p.sendPeersOnline, p.sendPeersWentOffline)
	defer func() {
		p.ctxCancel()
		p.notifier.RemoveListener(p.peersListener)

		if err := p.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.log.Errorf(errCloseConn, err)
		}
	}()

	ctx := p.ctx

	hc := p.newHealthCheckSender()
	go hc.StartHealthCheck(ctx)
	go p.handleHealthcheckEvents(ctx, hc)

	buf := make([]byte, bufferSize)
	for {
		n, err := p.conn.Read(ctx, buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.log.Errorf("failed to read message: %s", err)
			}
			return
		}

		if n == 0 {
			p.log.Errorf("received empty message")
			return
		}

		msg := buf[:n]

		if err := messages.ValidateConnectionVersion(msg, p.version); err != nil {
			p.log.Tracef("drop message: %s", err)
			continue
		}

		msgType, err := messages.DetermineClientMessageType(msg)
		if err != nil {
			p.log.Tracef("drop message: %s", err)
			continue
		}

		p.handleMsgType(ctx, msgType, hc, n, msg)
	}
}

func (p *Peer) ID() messages.PeerID {
	return p.id
}

// Version returns the protocol version selected for this connection
func (p *Peer) Version() messages.ProtocolVersion {
	return p.version
}

func (p *Peer) handleMsgType(ctx context.Context, msgType messages.MsgType, hc *healthcheck.Sender, n int, msg []byte) {
	switch msgType {
	case messages.MsgTypeHealthCheck:
		hc.OnHCResponse()
		p.handleHealthcheckEcho(msg, hc)
	case messages.MsgTypeTransport:
		p.metrics.TransferBytesRecv.Add(ctx, int64(n))
		p.metrics.PeerActivity(p.String())
		p.handleTransportMsg(msg)
	case messages.MsgTypeClose:
		p.log.Infof("peer exited gracefully")
		if err := p.conn.Close(); err != nil {
			log.Errorf(errCloseConn, err)
		}
	case messages.MsgTypeSubscribePeerState:
		p.handleSubscribePeerState(msg)
	case messages.MsgTypeUnsubscribePeerState:
		p.handleUnsubscribePeerState(msg)
	default:
		p.log.Tracef("drop %s message: not allowed after authentication", msgType)
	}
}

// Write writes data to the connection
func (p *Peer) Write(ctx context.Context, b []byte) (int, error) {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
	return p.conn.Write(ctx, b)
}

// CloseGracefully closes the connection with the peer gracefully. Send a close message to the client and close the
// connection.
func (p *Peer) CloseGracefully(ctx context.Context) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	err := p.writeWithTimeout(ctx, p.enc.CloseMsg())
	if err != nil {
		p.log.Errorf("failed to send close message to peer: %s", p.String())
	}

	p.ctxCancel()
	if err := p.conn.Close(); err != nil {
		p.log.Errorf(errCloseConn, err)
	}
}

func (p *Peer) Close() {
	p.ctxCancel()
	if err := p.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.log.Errorf(errCloseConn, err)
	}
}

// String returns the peer ID
func (p *Peer) String() string {
	return p.id.String()
}

// setAlignedSchedule turns the aligned heartbeat on for the connection with the
// verified signed phase of the handshake. A v1 connection always keeps the stock
// health check. Call it before Work.
func (p *Peer) setAlignedSchedule(v *verifiedPhase) {
	if v == nil || p.version < messages.ProtocolV2 {
		return
	}
	p.phase.Start(alignedhb.Answer(v.schedule), v.day)
	p.tuneTransport(v.schedule.Period)
}

// setPhaseVerifier sets the verifier and period limits for signed phases the
// client sends after the handshake. Without a verifier the connection stays as
// the handshake left it. Call it before Work.
func (p *Peer) setPhaseVerifier(v *phasesig.Verifier, limits alignedhb.PeriodLimits) {
	p.phaseVerifier = v
	p.periodLimits = limits
}

func (p *Peer) newHealthCheckSender() *healthcheck.Sender {
	if s, ok := p.phase.Schedule(); ok {
		return healthcheck.NewAlignedSender(p.log, healthcheck.AlignedSchedule(s))
	}
	return healthcheck.NewSender(p.log)
}

func (p *Peer) writeWithTimeout(ctx context.Context, buf []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := p.conn.Write(ctx, buf)
	return err
}

func (p *Peer) handleHealthcheckEvents(ctx context.Context, hc *healthcheck.Sender) {
	healthCheck := hc.HealthCheck
	for {
		select {
		case _, ok := <-healthCheck:
			if !ok {
				healthCheck = nil
				continue
			}
			p.phase.Tick()
			msg, aligned := p.healthcheckFrame()
			if _, err := p.Write(ctx, msg); err != nil {
				p.log.Errorf("failed to send healthcheck message: %s", err)
				p.Close()
				return
			}
			if aligned {
				p.hbMetrics().HeartbeatSent(ctx)
			}
		case _, ok := <-hc.Timeout:
			if !ok {
				return
			}
			p.log.Errorf("peer healthcheck timeout")
			err := p.conn.Close()
			if err != nil {
				p.log.Errorf("failed to close connection to peer: %s", err)
			}
			p.log.Info("peer connection closed due healthcheck timeout")
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *Peer) handleTransportMsg(msg []byte) {
	peerID, err := messages.UnmarshalTransportID(msg)
	if err != nil {
		p.log.Errorf("failed to unmarshal transport message: %s", err)
		return
	}

	item, ok := p.store.Peer(*peerID)
	if !ok {
		p.log.Debugf("peer not found: %s", peerID)
		return
	}
	dp := item.(*Peer)

	err = messages.UpdateTransportMsg(msg, dp.version, p.id)
	if err != nil {
		p.log.Errorf("failed to update transport message: %s", err)
		return
	}

	n, err := dp.Write(dp.ctx, msg)
	if err != nil {
		p.log.Errorf("failed to write transport message to: %s", dp.String())
		return
	}
	p.metrics.TransferBytesSent.Add(p.ctx, int64(n))
}

func (p *Peer) handleSubscribePeerState(msg []byte) {
	peerIDs, err := messages.UnmarshalSubPeerStateMsg(msg)
	if err != nil {
		p.log.Errorf("failed to unmarshal open connection message: %s", err)
		return
	}

	p.log.Debugf("received subscription message for %d peers", len(peerIDs))

	// collect online peers to response back to the caller
	p.notificationMutex.Lock()
	defer p.notificationMutex.Unlock()

	onlinePeers := p.store.GetOnlinePeersAndRegisterInterest(peerIDs, p.peersListener)
	if len(onlinePeers) == 0 {
		return
	}

	p.log.Debugf("response with %d online peers", len(onlinePeers))
	p.sendPeersOnline(onlinePeers)
}

func (p *Peer) handleUnsubscribePeerState(msg []byte) {
	peerIDs, err := messages.UnmarshalUnsubPeerStateMsg(msg)
	if err != nil {
		p.log.Errorf("failed to unmarshal open connection message: %s", err)
		return
	}

	p.peersListener.RemoveInterestedPeer(peerIDs)
}

func (p *Peer) sendPeersOnline(peers []messages.PeerID) {
	msgs, err := p.enc.PeersOnline(peers)
	if err != nil {
		p.log.Errorf("failed to marshal peers online message: %s", err)
		return
	}

	for n, msg := range msgs {
		if _, err := p.Write(p.ctx, msg); err != nil {
			p.log.Errorf("failed to write %d. peers online message: %s", n, err)
		}
	}
}

func (p *Peer) sendPeersWentOffline(peers []messages.PeerID) {
	p.notificationMutex.Lock()
	defer p.notificationMutex.Unlock()

	msgs, err := p.enc.PeersWentOffline(peers)
	if err != nil {
		p.log.Errorf("failed to marshal peers went offline message: %s", err)
		return
	}

	for n, msg := range msgs {
		if _, err := p.Write(p.ctx, msg); err != nil {
			p.log.Errorf("failed to write %d. peers went offline message: %s", n, err)
		}
	}
}
