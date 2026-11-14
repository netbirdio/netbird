package server

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// EnvPeerSessionEventsStartupGrace is a Go duration, such as "2m" or "90s", during which
	// a freshly started instance records no peer connect or disconnect events. "0" disables it.
	EnvPeerSessionEventsStartupGrace = "NB_PEER_SESSION_EVENTS_STARTUP_GRACE"

	defaultPeerSessionEventsStartupGrace = 2 * time.Minute
)

// peerSessionEventsStartupGrace reads the startup grace window once. A missing, negative or
// unparseable value falls back to the default, and the unparseable one is logged.
func peerSessionEventsStartupGrace() time.Duration {
	val := os.Getenv(EnvPeerSessionEventsStartupGrace)
	if val == "" {
		return defaultPeerSessionEventsStartupGrace
	}
	grace, err := time.ParseDuration(val)
	if err != nil {
		log.Warnf("failed to parse %s, using %s: %v", EnvPeerSessionEventsStartupGrace, defaultPeerSessionEventsStartupGrace, err)
		return defaultPeerSessionEventsStartupGrace
	}
	if grace < 0 {
		log.Warnf("%s must not be negative, using %s", EnvPeerSessionEventsStartupGrace, defaultPeerSessionEventsStartupGrace)
		return defaultPeerSessionEventsStartupGrace
	}
	return grace
}

// StartDraining marks the instance as shutting down, so peers disconnecting from here on
// leave no peer.disconnect event. It does not change what a disconnect writes.
func (am *DefaultAccountManager) StartDraining() {
	am.draining.Store(true)
}

// sessionEventsSuppressed reports whether peer session events are skipped: during the
// startup window, when every peer reconnects to the new instance, and while draining.
func (am *DefaultAccountManager) sessionEventsSuppressed(disconnect bool) bool {
	if time.Now().Before(am.sessionEventsFrom) {
		return true
	}
	return disconnect && am.draining.Load()
}
