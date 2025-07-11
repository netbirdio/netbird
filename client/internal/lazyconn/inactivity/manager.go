package inactivity

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

const (
	checkInterval = 1 * time.Minute

	DefaultInactivityThreshold = 15 * time.Minute
	MinimumInactivityThreshold = 1 * time.Minute
)

type WgInterface interface {
	LastActivities() map[string]time.Time
}

type Manager struct {
	inactivePeersChan chan map[string]struct{}

	iface               WgInterface
	interestedPeers     map[string]*lazyconn.PeerConfig
	inactivityThreshold time.Duration
}

func NewManager(iface WgInterface, configuredThreshold *time.Duration) *Manager {
	inactivityThreshold, err := validateInactivityThreshold(configuredThreshold)
	if err != nil {
		inactivityThreshold = DefaultInactivityThreshold
		log.Warnf("invalid inactivity threshold configured: %v, using default: %v", err, DefaultInactivityThreshold)
	}

	log.Infof("inactivity threshold configured: %v", inactivityThreshold)
	return &Manager{
		inactivePeersChan:   make(chan map[string]struct{}, 1),
		iface:               iface,
		interestedPeers:     make(map[string]*lazyconn.PeerConfig),
		inactivityThreshold: inactivityThreshold,
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
			idlePeers, err := m.checkStats()
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

func (m *Manager) checkStats() (map[string]struct{}, error) {
	lastActivities := m.iface.LastActivities()

	idlePeers := make(map[string]struct{})

	for peerID, peerCfg := range m.interestedPeers {
		lastActive, ok := lastActivities[peerID]
		if !ok {
			// when peer is in connecting state
			peerCfg.Log.Warnf("peer not found in wg stats")
			continue
		}

		if time.Since(lastActive) > m.inactivityThreshold {
			peerCfg.Log.Infof("peer is inactive since: %v", lastActive)
			idlePeers[peerID] = struct{}{}
		}
	}

	return idlePeers, nil
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
