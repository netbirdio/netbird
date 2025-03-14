package peer

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type stateDump struct {
	log *log.Entry

	sentOffer       int
	remoteOffer     int
	remoteAnswer    int
	remoteCandidate int
	mu              sync.Mutex
}

func newStateDump(log *log.Entry) *stateDump {
	return &stateDump{
		log: log,
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
	s.log.Infof("State dump: sentOffer=%d, remoteOffer=%d, remoteAnswer=%d, remoteCandidate=%d", s.sentOffer, s.remoteOffer, s.remoteAnswer, s.remoteCandidate)
}

func (s *stateDump) RemoteAnswer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteAnswer++
}
