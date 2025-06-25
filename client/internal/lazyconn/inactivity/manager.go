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
	InactivePeersChan chan []string

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
		InactivePeersChan:   make(chan []string, 1),
		iface:               iface,
		interestedPeers:     make(map[string]*lazyconn.PeerConfig),
		inactivityThreshold: inactivityThreshold,
	}
}

func (m *Manager) AddPeer(peerCfg *lazyconn.PeerConfig) {
	if _, exists := m.interestedPeers[peerCfg.PublicKey]; exists {
		return
	}

	peerCfg.Log.Debugf("adding peer to inactivity manager")
	m.interestedPeers[peerCfg.PublicKey] = peerCfg
}

func (m *Manager) RemovePeer(peer string) {
	pi, ok := m.interestedPeers[peer]
	if !ok {
		return
	}

	pi.Log.Debugf("remove peer from inactivity manager")
	delete(m.interestedPeers, peer)
}

func (m *Manager) Start(ctx context.Context) {
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

func (m *Manager) notifyInactivePeers(ctx context.Context, inactivePeers []string) {
	select {
	case m.InactivePeersChan <- inactivePeers:
	case <-ctx.Done():
		return
	default:
		return
	}
}

func (m *Manager) checkStats() ([]string, error) {
	lastActivities := m.iface.LastActivities()

	var idlePeers []string

	for peerID, peerCfg := range m.interestedPeers {
		lastActive, ok := lastActivities[peerID]
		if !ok {
			// when peer is in connecting state
			peerCfg.Log.Warnf("peer not found in wg stats")
			continue
		}

		if time.Since(lastActive) > m.inactivityThreshold {
			peerCfg.Log.Infof("peer is inactive since: %v", lastActive)
			idlePeers = append(idlePeers, peerID)
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
