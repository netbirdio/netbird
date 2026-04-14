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

// attempt processes a single ICE retry tick. It returns true if the caller should send an offer.
// When retries are exhausted it starts the hourly ticker and returns false once to signal the caller
// to swap the tick channel. Subsequent calls (from the hourly ticker) return true.
func (s *iceRetryState) attempt() bool {
	if s.hourly != nil {
		s.log.Debugf("hourly ICE retry attempt")
		return true
	}

	s.retries++
	if s.retries <= maxICERetries {
		s.log.Debugf("ICE retry attempt %d/%d", s.retries, maxICERetries)
		return true
	}

	s.log.Infof("ICE retries exhausted (%d/%d), switching to hourly retry", maxICERetries, maxICERetries)
	s.hourly = time.NewTicker(iceRetryInterval)
	return false
}

func (s *iceRetryState) hourlyC() <-chan time.Time {
	if s.hourly == nil {
		return nil
	}
	return s.hourly.C
}
