package inactivity

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/monotime"
)

const (
	checkInterval = 1 * time.Minute
	// tickSlack is how long past the expected aligned tick the fallback
	// check waits, so a tick that arrives a little late still runs the
	// check.
	tickSlack = 10 * time.Second

	DefaultInactivityThreshold = 15 * time.Minute
	MinimumInactivityThreshold = 1 * time.Minute

	// DefaultAlignedInactivityThreshold applies to the check on the aligned
	// heartbeat tick, which only mobile clients get. An idle peer there
	// wakes the phone with its keepalives, so it is closed after a few
	// seconds without traffic. The minimum matches the resolution of the
	// interface activity recorder.
	DefaultAlignedInactivityThreshold = 10 * time.Second
	MinimumAlignedInactivityThreshold = 5 * time.Second
)

var (
	stockLimits   = thresholdLimits{def: DefaultInactivityThreshold, min: MinimumInactivityThreshold}
	alignedLimits = thresholdLimits{def: DefaultAlignedInactivityThreshold, min: MinimumAlignedInactivityThreshold}
)

type WgInterface interface {
	LastActivities() map[string]monotime.Time
}

// TickSubscriber registers f to run on every aligned heartbeat tick, with
// the heartbeat period. f must not block. The returned func unregisters it.
type TickSubscriber func(f func(period time.Duration)) (unsubscribe func())

type Manager struct {
	inactivePeersChan chan map[string]struct{}

	iface WgInterface
	// inactivityThreshold applies to the timer check, tickThreshold to the
	// check on the aligned heartbeat tick.
	inactivityThreshold time.Duration
	tickThreshold       time.Duration
	subscribeTick       TickSubscriber

	// peersMu guards interestedPeers: the engine adds and removes peers
	// while the Start loop checks them.
	peersMu         sync.Mutex
	interestedPeers map[string]*watchedPeer

	// now is the clock for add times and idle checks, replaced in tests.
	now func() monotime.Time
}

// watchedPeer is a peer under inactivity watch. addedAt counts as activity:
// the interface keeps the last activity of a peer across a lazy close, so
// right after a reopen it still reports the traffic of the previous session.
type watchedPeer struct {
	cfg     *lazyconn.PeerConfig
	addedAt monotime.Time
}

// tickFeed carries the aligned heartbeat ticks into the Start loop. A nil c
// never delivers, so without a subscriber only the timer runs.
type tickFeed struct {
	c    chan time.Duration
	stop func()
}

type thresholdLimits struct {
	def time.Duration
	min time.Duration
}

// NewManager returns an inactivity manager that checks once per
// checkInterval with the stock threshold. With a subscribeTick it also
// checks on each aligned heartbeat tick, inside a wake the device has
// anyway, with the short aligned threshold. The timer then fires only
// while no tick arrives, so a client whose servers send no aligned
// heartbeat behaves as stock.
func NewManager(iface WgInterface, configuredThreshold *time.Duration, subscribeTick TickSubscriber) *Manager {
	inactivityThreshold := stockLimits.resolve(configuredThreshold)
	var tickThreshold time.Duration
	if subscribeTick != nil {
		tickThreshold = alignedLimits.resolve(configuredThreshold)
	}

	log.Infof("inactivity threshold configured: %v, on aligned tick: %v", inactivityThreshold, tickThreshold)
	return &Manager{
		inactivePeersChan:   make(chan map[string]struct{}, 1),
		iface:               iface,
		interestedPeers:     make(map[string]*watchedPeer),
		inactivityThreshold: inactivityThreshold,
		tickThreshold:       tickThreshold,
		subscribeTick:       subscribeTick,
		now:                 monotime.Now,
	}
}

func (m *Manager) InactivePeersChan() chan map[string]struct{} {
	if m == nil {
		// return a nil channel that blocks forever
		return nil
	}

	return m.inactivePeersChan
}

func (m *Manager) AddPeer(peerCfg *lazyconn.PeerConfig) {
	if m == nil {
		return
	}

	m.peersMu.Lock()
	defer m.peersMu.Unlock()

	if _, exists := m.interestedPeers[peerCfg.PublicKey]; exists {
		return
	}

	peerCfg.Log.Infof("adding peer to inactivity manager")
	m.interestedPeers[peerCfg.PublicKey] = &watchedPeer{cfg: peerCfg, addedAt: m.now()}
}

func (m *Manager) RemovePeer(peer string) {
	if m == nil {
		return
	}

	m.peersMu.Lock()
	defer m.peersMu.Unlock()

	pi, ok := m.interestedPeers[peer]
	if !ok {
		return
	}

	pi.cfg.Log.Debugf("remove peer from inactivity manager")
	delete(m.interestedPeers, peer)
}

func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}

	ticker := newTicker(checkInterval)
	defer ticker.Stop()

	ticks := m.startTicks()
	defer ticks.stop()

	for {
		threshold := m.inactivityThreshold
		onTick := false
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
		case period := <-ticks.c:
			// Push the fallback check out past the next expected tick, so
			// it only fires while the ticks stop.
			ticker.Reset(period + tickSlack)
			threshold = m.tickThreshold
			onTick = true
		}

		idlePeers, err := m.checkStats(threshold, onTick)
		if err != nil {
			log.Errorf("error checking stats: %v", err)
			return
		}

		if len(idlePeers) == 0 {
			continue
		}

		m.notifyInactivePeers(ctx, idlePeers)
	}
}

func (m *Manager) startTicks() tickFeed {
	if m.subscribeTick == nil {
		return tickFeed{stop: func() {}}
	}
	c := make(chan time.Duration, 1)
	unsubscribe := m.subscribeTick(func(period time.Duration) {
		if period <= 0 {
			return
		}
		// A check still waiting covers this tick too.
		select {
		case c <- period:
		default:
		}
	})
	return tickFeed{c: c, stop: unsubscribe}
}

func (m *Manager) notifyInactivePeers(ctx context.Context, inactivePeers map[string]struct{}) {
	select {
	case m.inactivePeersChan <- inactivePeers:
	case <-ctx.Done():
		return
	default:
		return
	}
}

func (m *Manager) checkStats(threshold time.Duration, onTick bool) (map[string]struct{}, error) {
	lastActivities := m.iface.LastActivities()

	idlePeers := make(map[string]struct{})

	m.peersMu.Lock()
	defer m.peersMu.Unlock()

	checkTime := time.Now()
	checkMono := m.now()
	for peerID, peer := range m.interestedPeers {
		lastActive, ok := lastActivities[peerID]
		if !ok {
			// when peer is in connecting state
			peer.cfg.Log.Warnf("peer not found in wg stats")
			continue
		}

		since := time.Duration(checkMono - idleFrom(lastActive, peer, onTick))
		if since > threshold {
			peer.cfg.Log.Infof("peer is inactive since time: %s", checkTime.Add(-since).String())
			idlePeers[peerID] = struct{}{}
		}
	}

	return idlePeers, nil
}

// idleFrom returns when the idle time of peer starts. On the aligned tick it
// is the later of the last activity and the open, so a freshly opened link
// gets the full short threshold; the timer check keeps the last activity
// alone, as stock.
func idleFrom(lastActive monotime.Time, peer *watchedPeer, onTick bool) monotime.Time {
	if !onTick {
		return lastActive
	}
	return max(lastActive, peer.addedAt)
}

// resolve validates a configured threshold against the limits, falling back
// to the default. A nil threshold yields the default.
func (l thresholdLimits) resolve(configuredThreshold *time.Duration) time.Duration {
	threshold, err := l.validate(configuredThreshold)
	if err != nil {
		log.Warnf("invalid inactivity threshold configured: %v, using default: %v", err, l.def)
		return l.def
	}
	return threshold
}

func (l thresholdLimits) validate(configuredThreshold *time.Duration) (time.Duration, error) {
	if configuredThreshold == nil {
		return l.def, nil
	}
	if *configuredThreshold < l.min {
		return 0, fmt.Errorf("configured inactivity threshold %v is too low, minimum %v", *configuredThreshold, l.min)
	}
	return *configuredThreshold, nil
}
