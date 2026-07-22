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
	// DefaultRetryInterval is how often the initiator retransmits its outstanding
	// message (offer, then confirm) while an exchange is in flight.
	DefaultRetryInterval = 2 * time.Second
	// DefaultMaxRetries bounds how many times the offer is retransmitted before the
	// exchange is declared failed. The convergence deadline is thus derived as
	// MaxRetries * RetryInterval — there is no separate deadline timer.
	DefaultMaxRetries = 10
	// DefaultMaxRekeyFailures is how many consecutive rekey (non-initial) failures
	// are tolerated before OnRekeyFailed. The initial exchange fails immediately.
	DefaultMaxRekeyFailures = 3
	// confirmRetransmits is how many times the initiator best-effort resends the
	// confirm after converging, to cover its loss without a dedicated goroutine.
	confirmRetransmits = 3
)

// Transport hands an already-encoded exchange message to the peer. The host routes
// it over the appropriate channel — Signal before the tunnel is up, the WireGuard
// tunnel for rekeys — so the driver never needs to know which is in use.
type Transport interface {
	Send(remoteWgKey string, msg []byte) error
}

// exchangeCtl tracks one in-flight exchange for a peer. A single lastSent holds the
// message currently being (re)transmitted: for the initiator it is the offer and
// then, once answered, the confirm; for the responder it is the answer, resent on a
// duplicate offer. Only the initiator runs a retransmit loop (cancel != nil); the
// responder is purely reactive.
type exchangeCtl struct {
	id        ExchangeID
	startedAt time.Time
	isInitial bool
	lastSent  []byte
	cancel    context.CancelFunc
	answered  bool // initiator: the answer arrived; retransmit phase is now the confirm
}

// Driver ties the pure Manager to the outside world: per-peer rekey timer, inbound
// dispatch, retransmit/convergence tracking, and surfacing events to the host via
// WGCallbackHandler.
type Driver struct {
	mgr       *Manager
	transport Transport
	wg        WGCallbackHandler
	logger    *slog.Logger

	rekeyInterval    time.Duration
	retryInterval    time.Duration
	maxRetries       int
	maxRekeyFailures int

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
// DefaultRekeyInterval; a nil logger falls back to slog.Default(). Retry/retries/K
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
		mgr:              NewManager(localWgKey),
		transport:        t,
		wg:               h,
		logger:           logger,
		rekeyInterval:    interval,
		retryInterval:    DefaultRetryInterval,
		maxRetries:       DefaultMaxRetries,
		maxRekeyFailures: DefaultMaxRekeyFailures,
		rootCtx:          ctx,
		rootCancel:       cancel,
		peers:            make(map[string]context.CancelFunc),
		exchanges:        make(map[string]*exchangeCtl),
		established:      make(map[string]bool),
		failures:         make(map[string]int),
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
		if ex.cancel != nil {
			ex.cancel()
		}
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

	ctx, cancel := context.WithCancel(d.rootCtx)
	d.mu.Lock()
	if old := d.exchanges[remoteWgKey]; old != nil && old.cancel != nil {
		old.cancel()
	}
	d.exchanges[remoteWgKey] = &exchangeCtl{
		id:        offer.ExchangeID,
		startedAt: time.Now(),
		isInitial: !d.established[remoteWgKey],
		lastSent:  raw,
		cancel:    cancel,
	}
	d.mu.Unlock()

	d.wait.Add(1)
	go d.initiatorLoop(ctx, remoteWgKey, offer.ExchangeID)

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
