package inalt

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/configurer"
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

	checkInterval     = 5 * time.Second
	idleThreshold     = 3
	idleCheckDuration = 3 * time.Minute

	// More conservative thresholds accounting for timing variations
	protocolOverheadBuffer = 1.5  // 50% buffer for timing variations and extra handshakes
	userTrafficMinimum     = 1024 // Minimum bytes to consider as actual user activity
)

type WgInterface interface {
	GetStats() (map[string]configurer.WGStats, error)
}

type peerInfo struct {
	lastRxBytesAtLastIdleCheck int64 // cumulative bytes at last 1-minute check
	idleCount                  int
	lastIdleCheckAt            time.Time

	recentTrafficSamples []int64
	maxSamples           int
}

type Manager struct {
	InactivePeersChan chan []string
	iface             WgInterface
	interestedPeers   map[string]*peerInfo

	// Dynamic thresholds based on expected patterns
	maxProtocolTraffic int64 // Maximum expected for protocol-only traffic
	minUserTraffic     int64 // Minimum to indicate actual user activity
}

func NewManager(iface WgInterface) *Manager {
	// Calculate maximum expected protocol overhead per check period
	numKeepAlives := int(idleCheckDuration / keepAliveInterval)

	// Worst case: multiple handshakes + all keep-alives
	// In 3 minutes we might see 1-2 handshakes due to timing variations
	maxHandshakes := 2
	maxProtocolBytes := int64(numKeepAlives*keepAliveBytes + maxHandshakes*(handshakeInitBytes+handshakeRespBytes))

	// Apply buffer for timing variations and edge cases
	maxProtocolWithBuffer := int64(float64(maxProtocolBytes) * protocolOverheadBuffer)

	// Set user traffic threshold significantly higher than protocol overhead
	minUserBytes := max(userTrafficMinimum, maxProtocolWithBuffer*2)

	log.Infof("--- Protocol thresholds - Max protocol overhead: %d bytes, Min user traffic: %d bytes",
		maxProtocolWithBuffer, minUserBytes)

	return &Manager{
		InactivePeersChan:  make(chan []string, 1),
		iface:              iface,
		interestedPeers:    make(map[string]*peerInfo),
		maxProtocolTraffic: maxProtocolWithBuffer,
		minUserTraffic:     minUserBytes,
	}
}

func (m *Manager) AddPeer(peer string) {
	if _, exists := m.interestedPeers[peer]; !exists {
		m.interestedPeers[peer] = &peerInfo{
			maxSamples: 5, // Keep last 5 traffic samples for trend analysis
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
		case <-ticker.C():
			idlePeers, err := m.checkStats()
			if err != nil {
				continue
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

func (m *Manager) checkStats() ([]string, error) {
	stats, err := m.iface.GetStats()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var idlePeers []string

	for peer, info := range m.interestedPeers {
		stat, found := stats[peer]
		if !found {
			continue
		}

		// First measurement: initialize
		if info.lastIdleCheckAt.IsZero() {
			info.lastIdleCheckAt = now
			info.lastRxBytesAtLastIdleCheck = stat.RxBytes
			continue
		}

		minDuration := idleCheckDuration - (checkInterval / 2)
		if now.Sub(info.lastIdleCheckAt) >= minDuration {
			rxDelta := stat.RxBytes - info.lastRxBytesAtLastIdleCheck
			info.lastRxBytesAtLastIdleCheck = stat.RxBytes

			// Store traffic sample for trend analysis
			info.recentTrafficSamples = append(info.recentTrafficSamples, rxDelta)
			if len(info.recentTrafficSamples) > info.maxSamples {
				info.recentTrafficSamples = info.recentTrafficSamples[1:]
			}

			log.Infof("--- RxBytes delta: %d, samples: %v", rxDelta, info.recentTrafficSamples)

			// Improved idle detection logic
			isIdle := m.evaluateIdleState(peer, info, rxDelta)

			if isIdle {
				info.idleCount++
			} else {
				info.idleCount = 0
			}

			info.lastIdleCheckAt = now

			if info.idleCount >= idleThreshold {
				idlePeers = append(idlePeers, peer)
				info.idleCount = 0 // reset after detecting idle
				log.Infof("--- detected as idle after %d consecutive checks", idleThreshold)
			}
		}
	}

	return idlePeers, nil
}

// evaluateIdleState determines if a peer is idle based on traffic patterns
func (m *Manager) evaluateIdleState(peer string, info *peerInfo, currentTraffic int64) bool {
	// Clear case: significant user traffic detected
	if currentTraffic >= m.minUserTraffic {
		log.Infof("--- active - user traffic detected: %d >= %d bytes", currentTraffic, m.minUserTraffic)
		return false
	}

	// Traffic is within protocol overhead range - likely idle
	if currentTraffic <= m.maxProtocolTraffic {
		log.Infof("--- idle - only protocol traffic: %d <= %d bytes", currentTraffic, m.maxProtocolTraffic)
		return true
	}

	// Traffic is between protocol overhead and user traffic thresholds
	// This is the ambiguous zone - use trend analysis if available
	if len(info.recentTrafficSamples) >= 3 {
		avgRecent := m.calculateAverage(info.recentTrafficSamples)
		maxRecent := m.findMaximum(info.recentTrafficSamples)

		// If recent average is consistently low and max is also low, likely idle
		if avgRecent <= float64(m.maxProtocolTraffic) && maxRecent <= m.maxProtocolTraffic {
			log.Infof("--- trending idle - avg: %.2f, max: %d, both <= %d bytes", avgRecent, maxRecent, m.maxProtocolTraffic)
			return true
		}

		// If we've seen user-level traffic recently, consider active
		if maxRecent >= m.minUserTraffic {
			log.Infof("--- %s recently active - max recent traffic: %d >= %d bytes", maxRecent, m.minUserTraffic)
			return false
		}
	}

	// In ambiguous cases with insufficient data, be conservative
	// Slight preference for idle since this traffic level suggests minimal activity
	log.Infof("--- %s ambiguous traffic %d bytes - assuming idle (between %d and %d)", currentTraffic, m.maxProtocolTraffic, m.minUserTraffic)
	return true
}

func (m *Manager) calculateAverage(samples []int64) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum int64
	for _, sample := range samples {
		sum += sample
	}
	return float64(sum) / float64(len(samples))
}

func (m *Manager) findMaximum(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	maxVal := samples[0]
	for _, sample := range samples[1:] {
		if sample > maxVal {
			maxVal = sample
		}
	}
	return maxVal
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
