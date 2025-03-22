package peer

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type stateDump struct {
	log    *log.Entry
	status *Status
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

func newStateDump(key string, log *log.Entry, statusRecorder *Status) *stateDump {
	return &stateDump{
		log:    log,
		status: statusRecorder,
		key:    key,
	}
}

func (s *stateDump) Start(ctx context.Context) {
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

func (s *stateDump) RemoteOffer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteOffer++
}

func (s *stateDump) RemoteCandidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteCandidate++
}

func (s *stateDump) SendOffer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sentOffer++
}

func (s *stateDump) dumpState() {
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

func (s *stateDump) RemoteAnswer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteAnswer++
}

func (s *stateDump) P2PConnected() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.p2pConnected++
}

func (s *stateDump) SwitchToRelay() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.switchToRelay++
}

func (s *stateDump) WGcheckSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.wgCheckSuccess++
}

func (s *stateDump) RelayConnected() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.relayConnected++
}

func (s *stateDump) NewLocalProxy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.localProxies++
}
