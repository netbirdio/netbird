package peer

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/metrics"
)

type MetricsStages struct {
	isReconnectionAttempt bool // Track if current attempt is a reconnection
	stageTimestamps       metrics.ConnectionStageTimestamps
	mu                    sync.Mutex
}

func (s *MetricsStages) RecordCreated() {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Infof("--- RecordCreated")
	s.stageTimestamps.Created = time.Now()
}

func (s *MetricsStages) RecordSemaphoreAcquired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Infof("--- RecordSemaphoreAcquired")
	s.stageTimestamps.SemaphoreAcquired = time.Now()
}

// RecordSignaling records the signaling timestamp when sending offers
// For initial connections: records when we start sending
// For reconnections: does nothing (we wait for RecordSignalingReceived)
func (s *MetricsStages) RecordSignaling() {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Infof("--- RecordSignaling (send)")

	if s.isReconnectionAttempt {
		return
	}

	if s.stageTimestamps.Signaling.IsZero() {
		log.Infof("--- Recorded Signaling (initial connection, sending)")
		s.stageTimestamps.Signaling = time.Now()
	}
}

// RecordSignalingReceived records the signaling timestamp when receiving offers/answers
// For reconnections: records when we receive the first signal
// For initial connections: does nothing (already recorded in RecordSignaling)
func (s *MetricsStages) RecordSignalingReceived() {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Infof("--- RecordSignalingReceived (receive)")

	// Only record for reconnections when we receive a signal
	if s.isReconnectionAttempt && s.stageTimestamps.Signaling.IsZero() {
		log.Infof("--- Recorded Signaling (reconnection, receiving)")
		s.stageTimestamps.Signaling = time.Now()
	}
}

func (s *MetricsStages) RecordConnectionReady() {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Infof("--- RecordConnectionReady")
	if s.stageTimestamps.ConnectionReady.IsZero() {
		log.Infof("--- Recorded ConnectionReady")
		s.stageTimestamps.ConnectionReady = time.Now()
	}

}

func (s *MetricsStages) RecordWGHandshakeSuccess(elapsed time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Infof("--- record: %v, %v", s.stageTimestamps.ConnectionReady, elapsed)
	if !s.stageTimestamps.ConnectionReady.IsZero() {
		// todo, check if it is earlier then ConnectionReady
		s.stageTimestamps.WgHandshakeSuccess = elapsed
	}
}

func (s *MetricsStages) Disconnected() {
	log.Infof("--- Disconnected")
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.stageTimestamps = metrics.ConnectionStageTimestamps{
		Created:           now,
		SemaphoreAcquired: now,
	}
	s.isReconnectionAttempt = true
}

func (s *MetricsStages) IsReconnection() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isReconnectionAttempt
}

func (s *MetricsStages) GetTimestamps() metrics.ConnectionStageTimestamps {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stageTimestamps
}
