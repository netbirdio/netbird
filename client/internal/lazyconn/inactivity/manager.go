package inactivity

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/monotime"
)

const (
	checkInterval = 1 * time.Minute

	// DefaultInactivityThreshold is the relay-tunnel idle-teardown
	// fallback when neither client config nor server-pushed value sets
	// it. Bumped 2026-05-03 from 15 min to 24 h: a 15-min window
	// triggered tear-down for peers that exchange traffic only
	// occasionally (e.g. NAT-keepalive only), forcing a full re-
	// handshake on every wake. 24 h matches the dashboard placeholder
	// and the production value most users actually want.
	DefaultInactivityThreshold = 24 * time.Hour
	MinimumInactivityThreshold = 1 * time.Minute
)

type WgInterface interface {
	LastActivities() map[string]monotime.Time
}

// Manager watches per-peer activity timestamps from the WireGuard
// interface and notifies via channels when peers cross inactivity
// thresholds.
//
// Phase 2 (#5989) introduced TWO independent thresholds per peer:
//   - iceTimeout fires the iceInactiveChan (consumer detaches the ICE
//     worker but keeps the relay-tunnel up).
//   - relayTimeout fires the relayInactiveChan (consumer tears down
//     the whole connection).
//
// Threshold == 0 disables that channel for all peers (the corresponding
// teardown never fires). Phase-1 p2p-lazy is expressed as
// iceTimeout=0 + relayTimeout=X; the legacy InactivePeersChan is the
// same as RelayInactiveChan for backwards compat.
type Manager struct {
	iface WgInterface

	// Two-timer thresholds (Phase 2). Both 0 = manager is effectively
	// inert (peers register but no channel ever fires).
	iceTimeout   time.Duration
	relayTimeout time.Duration

	interestedPeers map[string]*lazyconn.PeerConfig

	iceInactiveChan   chan map[string]struct{}
	relayInactiveChan chan map[string]struct{}

	// inactivityThreshold + inactivePeersChan are kept for the
	// Phase-1 NewManager API. Internally they alias to the relay
	// timeout / channel.
	inactivityThreshold time.Duration
	inactivePeersChan   chan map[string]struct{}
}

// NewManager is the Phase-1 single-timer constructor. Pass a *time.Duration
// to override the default DefaultInactivityThreshold; nil uses the default.
//
// Deprecated: use NewManagerWithTwoTimers. NewManager remains the entry
// point for callers that haven't been migrated; it constructs a manager
// with iceTimeout=0 (= ICE always-on, p2p-lazy semantics).
func NewManager(iface WgInterface, configuredThreshold *time.Duration) *Manager {
	threshold, err := validateInactivityThreshold(configuredThreshold)
	if err != nil {
		threshold = DefaultInactivityThreshold
		log.Warnf("invalid inactivity threshold configured: %v, using default: %v", err, DefaultInactivityThreshold)
	}

	log.Infof("inactivity threshold configured: %v", threshold)
	return newManager(iface, 0, threshold)
}

// NewManagerWithTwoTimers is the Phase-2 constructor. Pass 0 for either
// timeout to disable that teardown path. Both 0 leaves the manager
// running but inert (no channel ever fires) -- used by p2p / relay-forced
// modes that don't tear down workers.
func NewManagerWithTwoTimers(iface WgInterface, iceTimeout, relayTimeout time.Duration) *Manager {
	if iceTimeout > 0 {
		log.Infof("ICE inactivity timeout: %v", iceTimeout)
	}
	if relayTimeout > 0 {
		log.Infof("relay inactivity timeout: %v", relayTimeout)
	}
	return newManager(iface, iceTimeout, relayTimeout)
}

func newManager(iface WgInterface, iceTimeout, relayTimeout time.Duration) *Manager {
	relayCh := make(chan map[string]struct{}, 1)
	return &Manager{
		iface:               iface,
		iceTimeout:          iceTimeout,
		relayTimeout:        relayTimeout,
		interestedPeers:     make(map[string]*lazyconn.PeerConfig),
		iceInactiveChan:     make(chan map[string]struct{}, 1),
		relayInactiveChan:   relayCh,
		inactivityThreshold: relayTimeout,
		inactivePeersChan:   relayCh, // Phase-1 alias: same channel as relayInactiveChan
	}
}

// InactivePeersChan is the Phase-1 channel for whole-tunnel teardown.
// In the Phase-2 internal model this is the same channel as
// RelayInactiveChan -- existing callers (engine.go p2p-lazy path) keep
// working unchanged.
func (m *Manager) InactivePeersChan() chan map[string]struct{} {
	if m == nil {
		// return a nil channel that blocks forever
		return nil
	}

	return m.inactivePeersChan
}

// ICEInactiveChan returns the channel that signals ICE-worker-only
// inactivity per peer (consumer typically calls Conn.DetachICE).
// Always returns a valid channel; if iceTimeout is 0, the channel
// just never fires.
func (m *Manager) ICEInactiveChan() chan map[string]struct{} {
	if m == nil {
		return nil
	}
	return m.iceInactiveChan
}

// RelayInactiveChan returns the channel that signals relay-worker
// (and thus whole-tunnel) inactivity per peer.
func (m *Manager) RelayInactiveChan() chan map[string]struct{} {
	if m == nil {
		return nil
	}
	return m.relayInactiveChan
}

func (m *Manager) AddPeer(peerCfg *lazyconn.PeerConfig) {
	if m == nil {
		return
	}

	if _, exists := m.interestedPeers[peerCfg.PublicKey]; exists {
		return
	}

	peerCfg.Log.Infof("adding peer to inactivity manager")
	m.interestedPeers[peerCfg.PublicKey] = peerCfg
}

func (m *Manager) RemovePeer(peer string) {
	if m == nil {
		return
	}

	pi, ok := m.interestedPeers[peer]
	if !ok {
		return
	}

	pi.Log.Debugf("remove peer from inactivity manager")
	delete(m.interestedPeers, peer)
}

func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}

	ticker := newTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			iceIdle, relayIdle, err := m.checkStats()
			if err != nil {
				log.Errorf("error checking stats: %v", err)
				return
			}

			if len(iceIdle) > 0 {
				m.notifyChan(ctx, m.iceInactiveChan, iceIdle)
			}
			if len(relayIdle) > 0 {
				m.notifyChan(ctx, m.relayInactiveChan, relayIdle)
			}
		}
	}
}

func (m *Manager) notifyChan(ctx context.Context, ch chan map[string]struct{}, peers map[string]struct{}) {
	select {
	case ch <- peers:
	case <-ctx.Done():
		return
	default:
		return
	}
}

// checkStats walks the per-peer activity-since values and groups peers
// into two sets:
//   - iceIdle: peers idle longer than iceTimeout (only populated when
//     iceTimeout > 0; otherwise this set is always empty)
//   - relayIdle: peers idle longer than relayTimeout (only populated
//     when relayTimeout > 0)
//
// Both sets are returned independently so consumers can act on each
// without coupling. A peer that has crossed both thresholds appears in
// both sets and the consumer is expected to handle them in order
// (first DetachICE on the iceIdle set, then full Close on the relayIdle
// set; the order is fine because Close on a peer where ICE is already
// detached is still correct).
func (m *Manager) checkStats() (iceIdle, relayIdle map[string]struct{}, err error) {
	lastActivities := m.iface.LastActivities()

	iceIdle = make(map[string]struct{})
	relayIdle = make(map[string]struct{})

	checkTime := time.Now()
	for peerID, peerCfg := range m.interestedPeers {
		lastActive, ok := lastActivities[peerID]
		if !ok {
			// when peer is in connecting state
			peerCfg.Log.Warnf("peer not found in wg stats")
			continue
		}

		since := monotime.Since(lastActive)

		if m.iceTimeout > 0 && since > m.iceTimeout {
			peerCfg.Log.Debugf("peer ICE idle since: %s", checkTime.Add(-since).String())
			iceIdle[peerID] = struct{}{}
		}
		if m.relayTimeout > 0 && since > m.relayTimeout {
			peerCfg.Log.Infof("peer relay idle since: %s", checkTime.Add(-since).String())
			relayIdle[peerID] = struct{}{}
		}
	}

	return iceIdle, relayIdle, nil
}

func validateInactivityThreshold(configuredThreshold *time.Duration) (time.Duration, error) {
	if configuredThreshold == nil {
		return DefaultInactivityThreshold, nil
	}
	if *configuredThreshold < MinimumInactivityThreshold {
		return 0, fmt.Errorf("configured inactivity threshold %v is too low, using %v", *configuredThreshold, MinimumInactivityThreshold)
	}
	return *configuredThreshold, nil
}
