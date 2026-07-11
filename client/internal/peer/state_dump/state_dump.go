package state_dump

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/status"
)

type StateDump struct {
	log    *log.Entry
	status *status.Recorder
	key    string

	sentOffer       int
	remoteOffer     int
	remoteAnswer    int
	remoteCandidate int
	p2pConnected    int
	switchToRelay   int
	wgCheckSuccess  int
	relayConnected  int
	localProxies    int

	mu sync.Mutex
}

func NewStateDump(key string, log *log.Entry, statusRecorder *status.Recorder) *StateDump {
	return &StateDump{
		log:    log,
		status: statusRecorder,
		key:    key,
	}
}

func (s *StateDump) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.dumpState()
		case <-ctx.Done():
			return
		}
	}
}

func (s *StateDump) RemoteOffer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteOffer++
}

func (s *StateDump) RemoteCandidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteCandidate++
}

func (s *StateDump) SendOffer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sentOffer++
}

func (s *StateDump) dumpState() {
	s.mu.Lock()
	defer s.mu.Unlock()

	status := "unknown"
	state, e := s.status.GetPeer(s.key)
	if e == nil {
		status = state.ConnStatus.String()
	}

	s.log.Infof("Dump stat: Status: %s, SentOffer: %d, RemoteOffer: %d, RemoteAnswer: %d, RemoteCandidate: %d, P2PConnected: %d, SwitchToRelay: %d, WGCheckSuccess: %d, RelayConnected: %d, LocalProxies: %d",
		status, s.sentOffer, s.remoteOffer, s.remoteAnswer, s.remoteCandidate, s.p2pConnected, s.switchToRelay, s.wgCheckSuccess, s.relayConnected, s.localProxies)
}

func (s *StateDump) RemoteAnswer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteAnswer++
}

func (s *StateDump) P2PConnected() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.p2pConnected++
}

func (s *StateDump) SwitchToRelay() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.switchToRelay++
}

func (s *StateDump) WGcheckSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.wgCheckSuccess++
}

func (s *StateDump) RelayConnected() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.relayConnected++
}

func (s *StateDump) NewLocalProxy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.localProxies++
}
