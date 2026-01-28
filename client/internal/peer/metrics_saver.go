package peer

import (
	"sync"
	"time"

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
	s.stageTimestamps.Created = time.Now()
}

func (s *MetricsStages) RecordSemaphoreAcquired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stageTimestamps.SemaphoreAcquired = time.Now()
}

// RecordSignaling records the signaling timestamp when sending offers
// For initial connections: records when we start sending
// For reconnections: does nothing (we wait for RecordSignalingReceived)
func (s *MetricsStages) RecordSignaling() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isReconnectionAttempt {
		return
	}

	if s.stageTimestamps.Signaling.IsZero() {
		s.stageTimestamps.Signaling = time.Now()
	}
}

// RecordSignalingReceived records the signaling timestamp when receiving offers/answers
// For reconnections: records when we receive the first signal
// For initial connections: does nothing (already recorded in RecordSignaling)
func (s *MetricsStages) RecordSignalingReceived() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only record for reconnections when we receive a signal
	if s.isReconnectionAttempt && s.stageTimestamps.Signaling.IsZero() {
		s.stageTimestamps.Signaling = time.Now()
	}
}

func (s *MetricsStages) RecordConnectionReady(when time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stageTimestamps.ConnectionReady.IsZero() {
		s.stageTimestamps.ConnectionReady = when
	}
}

func (s *MetricsStages) RecordWGHandshakeSuccess(handshakeTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.stageTimestamps.ConnectionReady.IsZero() {
		// WireGuard only reports handshake times with second precision, but ConnectionReady
		// is captured with microsecond precision. If handshake appears before ConnectionReady
		// due to truncation (e.g., handshake at 6.042s truncated to 6.000s), normalize to
		// ConnectionReady to avoid negative duration metrics.
		if handshakeTime.Before(s.stageTimestamps.ConnectionReady) {
			s.stageTimestamps.WgHandshakeSuccess = s.stageTimestamps.ConnectionReady
		} else {
			s.stageTimestamps.WgHandshakeSuccess = handshakeTime
		}
	}
}

// Disconnected sets the mode to reconnection. It is called only when both ICE and Relay have been disconnected at the same time.
func (s *MetricsStages) Disconnected() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset all timestamps for reconnection
	// For reconnections, we only track from Signaling onwards
	// This avoids meaningless creation→semaphore and semaphore→signaling metrics
	s.stageTimestamps = metrics.ConnectionStageTimestamps{}
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
