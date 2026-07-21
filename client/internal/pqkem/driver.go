package pqkem

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultRekeyInterval matches WireGuard's own REKEY_AFTER_TIME so the freshly
	// rotated PSK is naturally adopted by WG's next handshake without forcing one.
	DefaultRekeyInterval = 2 * time.Minute
	// DefaultRetryInterval is how often an in-flight exchange retransmits.
	DefaultRetryInterval = 2 * time.Second
	// DefaultConvergenceTimeout bounds a single exchange before it is declared failed.
	DefaultConvergenceTimeout = 20 * time.Second
	// DefaultMaxRekeyFailures is how many consecutive rekey (non-initial) failures are
	// tolerated before OnRekeyFailed is raised. The initial exchange fails immediately.
	DefaultMaxRekeyFailures = 3
	// confirmRetransmits is how many extra times the initiator best-effort resends the
	// confirm (the exchange's unacked last message) to reduce a stuck responder.
	confirmRetransmits = 3
)

// Transport hands an already-encoded exchange message to the peer. The host routes
// it over the appropriate channel — Signal before the tunnel is up, the WireGuard
// tunnel for rekeys — so the driver never needs to know which is in use.
type Transport interface {
	Send(remoteWgKey string, msg []byte) error
}

type encodableMsg interface {
	Encode() ([]byte, error)
}

// exchangeCtl tracks one in-flight exchange for a peer: its id, the cancel for its
// retransmit/deadline goroutine, when it started (for convergence latency) and
// whether it is the peer's first (initial) exchange (which fails hard on timeout).
type exchangeCtl struct {
	id        ExchangeID
	cancel    context.CancelFunc
	startedAt time.Time
	isInitial bool
}

// Driver ties the pure Manager to the outside world: per-peer rekey timer, inbound
// dispatch, retransmit/convergence tracking, and surfacing events to the host via
// WGCallbackHandler.
type Driver struct {
	mgr       *Manager
	transport Transport
	wg        WGCallbackHandler
	logger    *slog.Logger

	rekeyInterval      time.Duration
	retryInterval      time.Duration
	convergenceTimeout time.Duration
	maxRekeyFailures   int

	rootCtx    context.Context
	rootCancel context.CancelFunc

	mu          sync.Mutex
	peers       map[string]context.CancelFunc // per-peer rekey loop
	exchanges   map[string]*exchangeCtl       // in-flight exchange per peer
	established map[string]bool               // peer has completed at least one exchange
	failures    map[string]int                // consecutive rekey failures per peer
	wait        sync.WaitGroup
}

// NewDriver builds a driver for the local peer. A zero interval falls back to
// DefaultRekeyInterval; a nil logger falls back to slog.Default(). Retry/timeout/K
// use their defaults and can be overridden on the returned struct before use.
func NewDriver(localWgKey string, t Transport, h WGCallbackHandler, interval time.Duration, logger *slog.Logger) *Driver {
	if interval <= 0 {
		interval = DefaultRekeyInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Driver{
		mgr:                NewManager(localWgKey),
		transport:          t,
		wg:                 h,
		logger:             logger,
		rekeyInterval:      interval,
		retryInterval:      DefaultRetryInterval,
		convergenceTimeout: DefaultConvergenceTimeout,
		maxRekeyFailures:   DefaultMaxRekeyFailures,
		rootCtx:            ctx,
		rootCancel:         cancel,
		peers:              make(map[string]context.CancelFunc),
		exchanges:          make(map[string]*exchangeCtl),
		established:        make(map[string]bool),
		failures:           make(map[string]int),
	}
}

// AddPeer registers a remote peer and starts its rekey timer. Re-adding is a no-op.
func (d *Driver) AddPeer(remoteWgKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.peers[remoteWgKey]; ok {
		return
	}
	ctx, cancel := context.WithCancel(d.rootCtx)
	d.peers[remoteWgKey] = cancel
	d.wait.Add(1)
	go d.rekeyLoop(ctx, remoteWgKey)
}

// RemovePeer stops a peer's rekey timer and any in-flight exchange, and drops state.
func (d *Driver) RemovePeer(remoteWgKey string) {
	d.mu.Lock()
	if cancel, ok := d.peers[remoteWgKey]; ok {
		cancel()
		delete(d.peers, remoteWgKey)
	}
	if ex, ok := d.exchanges[remoteWgKey]; ok {
		ex.cancel()
		delete(d.exchanges, remoteWgKey)
	}
	delete(d.established, remoteWgKey)
	delete(d.failures, remoteWgKey)
	d.mu.Unlock()
}

// Stop cancels all timers and in-flight exchanges and waits for goroutines to exit.
func (d *Driver) Stop() {
	d.rootCancel()
	d.wait.Wait()
	d.mu.Lock()
	d.peers = make(map[string]context.CancelFunc)
	d.exchanges = make(map[string]*exchangeCtl)
	d.mu.Unlock()
}

// HandleInbound decodes an incoming message and drives the exchange, sending any
// response via the transport and surfacing derived PSKs / convergence to the host.
func (d *Driver) HandleInbound(remoteWgKey string, raw []byte) error {
	typ, msg, err := Decode(raw)
	if err != nil {
		return fmt.Errorf("decode from %s: %w", remoteWgKey, err)
	}

	switch typ {
	case MsgOffer:
		return d.handleOffer(remoteWgKey, msg.(*OfferMsg))
	case MsgAnswer:
		return d.handleAnswer(remoteWgKey, msg.(*AnswerMsg))
	case MsgConfirm:
		return d.handleConfirm(remoteWgKey, msg.(*ConfirmMsg))
	default:
		return fmt.Errorf("unhandled message type %d from %s", typ, remoteWgKey)
	}
}

func (d *Driver) handleOffer(remoteWgKey string, o *OfferMsg) error {
	answer, err := d.mgr.HandleOffer(remoteWgKey, o)
	if err != nil {
		return err
	}
	// Arm a responder exchange (deadline waiting for the confirm) unless one for this
	// id is already armed — a retransmitted offer just re-sends the same answer.
	d.armExchange(remoteWgKey, o.ExchangeID, nil)
	return d.send(remoteWgKey, answer)
}

func (d *Driver) handleAnswer(remoteWgKey string, a *AnswerMsg) error {
	psk, confirm, err := d.mgr.HandleAnswer(remoteWgKey, a)
	if err != nil {
		return err
	}
	if err := d.wg.OnNewPSKReady(remoteWgKey, psk); err != nil {
		return err
	}
	// Initiator has the PSK now -> this side has converged.
	d.onConverged(remoteWgKey, a.ExchangeID)
	if err := d.send(remoteWgKey, confirm); err != nil {
		return err
	}
	d.retransmitConfirm(remoteWgKey, confirm)
	return nil
}

func (d *Driver) handleConfirm(remoteWgKey string, c *ConfirmMsg) error {
	psk, err := d.mgr.HandleConfirm(remoteWgKey, c)
	if err != nil {
		return err
	}
	if err := d.wg.OnNewPSKReady(remoteWgKey, psk); err != nil {
		return err
	}
	d.onConverged(remoteWgKey, c.ExchangeID)
	return nil
}

// initiateRekey starts a fresh exchange when the local peer is the initiator for
// this remote peer; the responder waits for the offer instead. Exposed (unexported
// but directly callable) so tests can drive a rekey without waiting on the ticker.
func (d *Driver) initiateRekey(remoteWgKey string) error {
	if !d.mgr.IsInitiator(remoteWgKey) {
		return nil
	}
	offer, err := d.mgr.StartExchange(remoteWgKey)
	if err != nil {
		return err
	}
	raw, err := offer.Encode()
	if err != nil {
		return err
	}
	d.armExchange(remoteWgKey, offer.ExchangeID, raw)
	return d.transport.Send(remoteWgKey, raw)
}

func (d *Driver) rekeyLoop(ctx context.Context, remoteWgKey string) {
	defer d.wait.Done()
	t := time.NewTicker(d.rekeyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.initiateRekey(remoteWgKey); err != nil {
				d.logger.Error("pqkem rekey failed to start", "peer", remoteWgKey, "err", err)
			}
		}
	}
}

func (d *Driver) send(remoteWgKey string, m encodableMsg) error {
	raw, err := m.Encode()
	if err != nil {
		return err
	}
	return d.transport.Send(remoteWgKey, raw)
}
