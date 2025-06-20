package inactivity

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

// Responder: vmp2
// - Receive handshake initiation: 148 bytes + extra 32 bytes, every 02:00 - 03:00 minutes
// - Receive keep alive: 32 bytes, every 25 sec
// Initiator: mp1
// - Receive handshake response:
// - Receive keep alive: 32 bytes, every 25 sec

const (
	keepAliveBytes       = 32
	keepAliveInterval    = 25 * time.Second
	handshakeInitBytes   = 148
	handshakeRespBytes   = 92
	handshakeMaxInterval = 3 * time.Minute

	checkInterval        = keepAliveInterval // todo: 5 * time.Second
	keepAliveCheckPeriod = keepAliveInterval

	inactivityThreshold = 3 // number of checks to consider peer inactive
)

const (
	// todo make it configurable
	DefaultInactivityThreshold = 60 * time.Minute // idle after 1 hour inactivity
	MinimumInactivityThreshold = 3 * time.Minute
)

type WgInterface interface {
	GetStats() (map[string]configurer.WGStats, error)
}

type peerInfo struct {
	lastRxBytesAtLastIdleCheck int64
	lastIdleCheckAt            time.Time
	inActivityInRow            int
	log                        *log.Entry
}

type Manager struct {
	InactivePeersChan chan []string
	iface             WgInterface
	interestedPeers   map[string]*peerInfo
}

func NewManager(iface WgInterface) *Manager {
	return &Manager{
		InactivePeersChan: make(chan []string, 1),
		iface:             iface,
		interestedPeers:   make(map[string]*peerInfo),
	}
}

func (m *Manager) AddPeer(peerCfg *lazyconn.PeerConfig) {
	if _, exists := m.interestedPeers[peerCfg.PublicKey]; exists {
		return
	}

	peerCfg.Log.Debugf("adding peer to inactivity manager")
	m.interestedPeers[peerCfg.PublicKey] = &peerInfo{
		log: peerCfg.Log,
	}
}

func (m *Manager) RemovePeer(peer string) {
	pi, ok := m.interestedPeers[peer]
	if !ok {
		return
	}

	pi.log.Debugf("remove peer from inactivity manager")
	delete(m.interestedPeers, peer)
}

func (m *Manager) Start(ctx context.Context) {
	ticker := newTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case tickTime := <-ticker.C():
			idlePeers, err := m.checkStats(tickTime)
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

func (m *Manager) checkStats(now time.Time) ([]string, error) {
	stats, err := m.iface.GetStats()
	if err != nil {
		return nil, err
	}

	var idlePeers []string

	for peer, info := range m.interestedPeers {
		stat, found := stats[peer]
		if !found {
			// when peer is in connecting state
			info.log.Warnf("peer not found in wg stats")
		}

		// First measurement: initialize
		if info.lastIdleCheckAt.IsZero() {
			info.lastIdleCheckAt = now
			info.lastRxBytesAtLastIdleCheck = stat.RxBytes
			info.log.Infof("initializing RxBytes: %v, %v", now, stat.RxBytes)
			continue
		}

		// check only every idleCheckDuration
		if shouldSkipIdleCheck(now, info.lastIdleCheckAt) {
			continue
		}

		// sometimes we measure false inactivity, so we need to check if we have inactivity in a row
		if isInactive(stat, info) {
			info.inActivityInRow++
		} else {
			info.inActivityInRow = 0
		}

		info.log.Infof("peer inactivity counter: %d", info.inActivityInRow)
		if info.inActivityInRow >= inactivityThreshold {
			info.log.Infof("peer is inactive for %d checks, marking as inactive", info.inActivityInRow)
			idlePeers = append(idlePeers, peer)
			info.inActivityInRow = 0
		}
		info.lastIdleCheckAt = now
		info.lastRxBytesAtLastIdleCheck = stat.RxBytes
	}

	return idlePeers, nil
}

func isInactive(stat configurer.WGStats, info *peerInfo) bool {
	rxSyncPrevPeriod := stat.RxBytes - info.lastRxBytesAtLastIdleCheck

	// when the peer reconnected we lose the rx bytes from between the reset and the last check.
	// We will suppose the peer was active
	if rxSyncPrevPeriod < 0 {
		info.log.Debugf("rxBytes decreased, resetting last rxBytes at last idle check")
		return false
	}

	switch rxSyncPrevPeriod {
	case 0:
		info.log.Debugf("peer inactive, received 0 bytes")
		return true
	case keepAliveBytes:
		info.log.Debugf("peer inactive, only keep alive received, current RxBytes: %d", rxSyncPrevPeriod)
		return true
	case handshakeInitBytes + keepAliveBytes:
		info.log.Debugf("peer inactive, only handshakeInitBytes + keepAliveBytes, current RxBytes: %d", rxSyncPrevPeriod)
		return true
	case handshakeRespBytes + keepAliveBytes:
		info.log.Debugf("peer inactive, only handshakeRespBytes + keepAliveBytes, current RxBytes: %d", rxSyncPrevPeriod)
		return true
	default:
		info.log.Infof("active, RxBytes: %d", rxSyncPrevPeriod)
		return false
	}
}

func shouldSkipIdleCheck(now, lastIdleCheckAt time.Time) bool {
	minDuration := keepAliveCheckPeriod - (checkInterval / 2)
	return now.Sub(lastIdleCheckAt) < minDuration
}
