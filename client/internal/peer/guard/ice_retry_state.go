package guard

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// maxICERetries is the maximum number of ICE offer attempts when relay is connected
	maxICERetries = 3
	// iceRetryInterval is the periodic retry interval after ICE retries are exhausted
	iceRetryInterval = 1 * time.Hour
)

// iceRetryState tracks the limited ICE retry attempts when relay is already connected.
// After maxICERetries attempts it switches to a periodic hourly retry.
type iceRetryState struct {
	log     *log.Entry
	retries int
	hourly  *time.Ticker
}

func (s *iceRetryState) reset() {
	s.retries = 0
	if s.hourly != nil {
		s.hourly.Stop()
		s.hourly = nil
	}
}

// shouldRetry reports whether the caller should send another ICE offer on this tick.
// Returns false when the per-cycle retry budget is exhausted and the caller must switch
// to the hourly ticker via enterHourlyMode + hourlyC.
func (s *iceRetryState) shouldRetry() bool {
	if s.hourly != nil {
		s.log.Debugf("hourly ICE retry attempt")
		return true
	}

	s.retries++
	if s.retries <= maxICERetries {
		s.log.Debugf("ICE retry attempt %d/%d", s.retries, maxICERetries)
		return true
	}

	return false
}

// enterHourlyMode starts the hourly retry ticker. Must be called after shouldRetry returns false.
func (s *iceRetryState) enterHourlyMode() {
	s.log.Infof("ICE retries exhausted (%d/%d), switching to hourly retry", maxICERetries, maxICERetries)
	s.hourly = time.NewTicker(iceRetryInterval)
}

func (s *iceRetryState) hourlyC() <-chan time.Time {
	if s.hourly == nil {
		return nil
	}
	return s.hourly.C
}
