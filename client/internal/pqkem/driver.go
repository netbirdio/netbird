package pqkem

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DefaultRekeyInterval matches WireGuard's own REKEY_AFTER_TIME so the freshly
// rotated PSK is naturally adopted by WG's next handshake without forcing one.
const DefaultRekeyInterval = 2 * time.Minute

// Transport hands an already-encoded exchange message to the peer. The host routes
// it over the appropriate channel — Signal before the tunnel is up, the WireGuard
// tunnel for rekeys — so the driver never needs to know which is in use.
type Transport interface {
	Send(remoteWgKey string, msg []byte) error
}

// encodableMsg is the common shape of the three wire messages, letting the driver
// send any of them uniformly.
type encodableMsg interface {
	Encode() ([]byte, error)
}

// Driver ties the pure Manager to the outside world: it runs the per-peer rekey
// timer, dispatches inbound messages, and surfaces the derived PSK to the host via
// WGCallbackHandler. Convergence/retry/OnRekeyFailed are layered on in a later step.
type Driver struct {
	mgr       *Manager
	transport Transport
	wg        WGCallbackHandler
	interval  time.Duration
	logger    *slog.Logger

	mu    sync.Mutex
	peers map[string]context.CancelFunc
	wait  sync.WaitGroup
}

// NewDriver builds a driver for the local peer. A zero interval falls back to
// DefaultRekeyInterval; a nil logger falls back to slog.Default().
func NewDriver(localWgKey string, t Transport, h WGCallbackHandler, interval time.Duration, logger *slog.Logger) *Driver {
	if interval <= 0 {
		interval = DefaultRekeyInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Driver{
		mgr:       NewManager(localWgKey),
		transport: t,
		wg:        h,
		interval:  interval,
		logger:    logger,
		peers:     make(map[string]context.CancelFunc),
	}
}

// AddPeer registers a remote peer and starts its rekey timer. Re-adding an existing
// peer is a no-op.
func (d *Driver) AddPeer(remoteWgKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.peers[remoteWgKey]; ok {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.peers[remoteWgKey] = cancel
	d.wait.Add(1)
	go d.rekeyLoop(ctx, remoteWgKey)
}

// RemovePeer stops a peer's rekey timer and drops its state.
func (d *Driver) RemovePeer(remoteWgKey string) {
	d.mu.Lock()
	cancel, ok := d.peers[remoteWgKey]
	delete(d.peers, remoteWgKey)
	d.mu.Unlock()
	if ok {
		cancel()
	}
}

// Stop cancels all peer timers and waits for their goroutines to exit.
func (d *Driver) Stop() {
	d.mu.Lock()
	for _, cancel := range d.peers {
		cancel()
	}
	d.peers = make(map[string]context.CancelFunc)
	d.mu.Unlock()
	d.wait.Wait()
}

// HandleInbound decodes an incoming message and drives the exchange, sending any
// response via the transport and surfacing a derived PSK through the callback.
func (d *Driver) HandleInbound(remoteWgKey string, raw []byte) error {
	typ, msg, err := Decode(raw)
	if err != nil {
		return fmt.Errorf("decode from %s: %w", remoteWgKey, err)
	}

	switch typ {
	case MsgOffer:
		answer, err := d.mgr.HandleOffer(remoteWgKey, msg.(*OfferMsg))
		if err != nil {
			return err
		}
		return d.send(remoteWgKey, answer)

	case MsgAnswer:
		psk, confirm, err := d.mgr.HandleAnswer(remoteWgKey, msg.(*AnswerMsg))
		if err != nil {
			return err
		}
		if err := d.wg.OnNewPSKReady(remoteWgKey, psk); err != nil {
			return err
		}
		return d.send(remoteWgKey, confirm)

	case MsgConfirm:
		psk, err := d.mgr.HandleConfirm(remoteWgKey, msg.(*ConfirmMsg))
		if err != nil {
			return err
		}
		return d.wg.OnNewPSKReady(remoteWgKey, psk)

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
	return d.send(remoteWgKey, offer)
}

func (d *Driver) rekeyLoop(ctx context.Context, remoteWgKey string) {
	defer d.wait.Done()
	t := time.NewTicker(d.interval)
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
