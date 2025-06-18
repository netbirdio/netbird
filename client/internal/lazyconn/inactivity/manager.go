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
	if _, exists := m.interestedPeers[peerCfg.PublicKey]; !exists {
		m.interestedPeers[peerCfg.PublicKey] = &peerInfo{
			log: peerCfg.Log,
		}
	}
}

func (m *Manager) RemovePeer(peer string) {
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
			select {
			case m.InactivePeersChan <- idlePeers:
			case <-ctx.Done():
				continue
			default:
				continue
			}
		}
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
			info.log.Warnf("peer not found in wg stats")
			continue
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

		// sometimes we measure false inactivity, so we need to check if we have activity in a row
		inactive := isInactive(stat, info)
		if inactive {
			info.inActivityInRow++
		} else {
			info.inActivityInRow = 0
		}

		if info.inActivityInRow >= 3 {
			info.log.Infof("peer is inactive for %d checks, marking as inactive", info.inActivityInRow)
			idlePeers = append(idlePeers, peer)
		}
		info.lastIdleCheckAt = now
		info.lastRxBytesAtLastIdleCheck = stat.RxBytes
	}

	return idlePeers, nil
}

func isInactive(stat configurer.WGStats, info *peerInfo) bool {
	rxSyncPrevPeriod := stat.RxBytes - info.lastRxBytesAtLastIdleCheck
	switch rxSyncPrevPeriod {
	case 0:
		info.log.Tracef("peer inactive, received 0 bytes")
		return true
	case keepAliveBytes:
		info.log.Tracef("peer inactive, only keep alive received, current RxBytes: %d", rxSyncPrevPeriod)
		return true
	case handshakeInitBytes + keepAliveBytes:
		info.log.Tracef("peer inactive, only handshakeInitBytes + keepAliveBytes, current RxBytes: %d", rxSyncPrevPeriod)
		return true
	case handshakeRespBytes + keepAliveBytes:
		info.log.Tracef("peer inactive, only handshakeRespBytes + keepAliveBytes, current RxBytes: %d", rxSyncPrevPeriod)
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
