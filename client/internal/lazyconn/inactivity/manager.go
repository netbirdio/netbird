package inactivity

import (
	"container/list"
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
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

	checkInterval = 1 * time.Minute
	historySize   = 5 * time.Minute

	DefaultInactivityThreshold = 15 * time.Minute
	MinimumInactivityThreshold = 5 * time.Minute

	recorderEnv = "NB_LAZYCONN_RECORDER_ENABLED"
)

type WgInterface interface {
	GetStats() (map[string]configurer.WGStats, error)
}

type peerHistory struct {
	lastRxBytes       int64      // last received bytes
	bytesHistory      *list.List // linked list of int64
	historySize       int
	summarizedBytes   int64
	inactivityCounter int // counter to track inactivity
	log               *log.Entry
}

func newPeerHistory(log *log.Entry, historySize int) *peerHistory {
	return &peerHistory{
		bytesHistory: list.New(),
		historySize:  historySize,
		log:          log,
	}
}

func (pi *peerHistory) appendRxBytes(rxBytes int64) {
	// If at capacity, remove the oldest element (front)
	if pi.bytesHistory.Len() == pi.historySize {
		pi.summarizedBytes -= pi.bytesHistory.Front().Value.(int64)
		pi.bytesHistory.Remove(pi.bytesHistory.Front())
	}

	// Add the new rxBytes at the back
	pi.bytesHistory.PushBack(rxBytes)
	pi.summarizedBytes += rxBytes
}

func (pi *peerHistory) historyString() string {
	var history []string
	for e := pi.bytesHistory.Front(); e != nil; e = e.Next() {
		history = append(history, fmt.Sprintf("%d", e.Value.(int64)))
	}
	return fmt.Sprintf("%s", history)
}

func (pi *peerHistory) reset() {
	for e := pi.bytesHistory.Front(); e != nil; e = e.Next() {
		e.Value = int64(0)
	}
	pi.summarizedBytes = 0
}

type Manager struct {
	InactivePeersChan chan []string
	iface             WgInterface
	interestedPeers   map[string]*peerHistory

	maxBytesPerPeriod int64
	historySize       int // Size of the history buffer for each peer, used to track received bytes over time
	recorder          *Recorder

	thresholdOfInactivity int // Number of consecutive checks with low activity to consider a peer inactive
}

func NewManager(iface WgInterface, configuredThreshold *time.Duration) *Manager {
	inactivityThreshold, err := validateInactivityThreshold(configuredThreshold)
	if err != nil {
		inactivityThreshold = DefaultInactivityThreshold
		log.Warnf("invalid inactivity threshold configured: %v, using default: %v", err, DefaultInactivityThreshold)
	}

	expectedMaxBytes := calculateExpectedMaxBytes()
	log.Infof("receive less than %d bytes per %v, will be considered inactive", expectedMaxBytes, inactivityThreshold)
	return &Manager{
		InactivePeersChan:     make(chan []string, 1),
		iface:                 iface,
		interestedPeers:       make(map[string]*peerHistory),
		historySize:           int(historySize.Minutes()),
		maxBytesPerPeriod:     expectedMaxBytes,
		thresholdOfInactivity: int(math.Ceil(inactivityThreshold.Minutes() / checkInterval.Minutes())),
	}
}

func (m *Manager) AddPeer(peerCfg *lazyconn.PeerConfig) {
	if _, exists := m.interestedPeers[peerCfg.PublicKey]; exists {
		return
	}

	peerCfg.Log.Debugf("adding peer to inactivity manager")
	m.interestedPeers[peerCfg.PublicKey] = newPeerHistory(peerCfg.Log, m.historySize)
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
	enabled, err := strconv.ParseBool(os.Getenv(recorderEnv))
	if err == nil && enabled {
		m.recorder = NewRecorder()
		defer m.recorder.Close()
	}

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

	for peer, history := range m.interestedPeers {
		stat, found := stats[peer]
		if !found {
			// when peer is in connecting state
			history.log.Warnf("peer not found in wg stats")
		}

		deltaRx := stat.RxBytes - history.lastRxBytes
		if deltaRx < 0 {
			deltaRx = 0 // reset to zero if negative
			history.reset()
		}

		m.recorder.ReceivedBytes(peer, now, deltaRx)

		history.lastRxBytes = stat.RxBytes
		history.appendRxBytes(deltaRx)

		// not enough history to determine inactivity
		if history.bytesHistory.Len() < m.historySize {
			history.log.Debugf("not enough history to determine inactivity, current history size: %d, required: %d", history.bytesHistory.Len(), m.historySize)
			continue
		}

		if history.summarizedBytes <= m.maxBytesPerPeriod {
			history.inactivityCounter++
			history.log.Debugf("peer is inactive, summarizedBytes: %d, maxBytesPerPeriod: %d, %v", history.summarizedBytes, m.maxBytesPerPeriod, history.historyString())
		} else {
			history.inactivityCounter = 0 // reset inactivity counter if activity is detected
			history.log.Debugf("peer is active, summarizedBytes: %d, maxBytesPerPeriod: %d, %v", history.summarizedBytes, m.maxBytesPerPeriod, history.historyString())
		}

		if history.inactivityCounter >= m.thresholdOfInactivity {
			history.log.Infof("peer is inactive for %d consecutive checks, marking as idle (limit %d) ", history.inactivityCounter, m.thresholdOfInactivity)
			idlePeers = append(idlePeers, peer)
			history.inactivityCounter = 0 // reset inactivity counter after marking as idle
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

func calculateExpectedMaxBytes() int64 {
	// Calculate number of keep-alive packets expected
	keepAliveCount := int64(historySize.Seconds() / keepAliveInterval.Seconds())
	keepAliveBytes := keepAliveCount * keepAliveBytes

	// Calculate potential handshake packets (conservative estimate)
	handshakeCount := int64(historySize.Minutes() / handshakeMaxInterval.Minutes())
	handshakeBytes := handshakeCount * (handshakeInitBytes + keepAliveBytes) // handshake + extra bytes

	return keepAliveBytes + handshakeBytes
}
