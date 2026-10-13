package client

import (
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// envRelayedSwitchDelay sets how long a routing peer that dropped from a
	// direct to a relayed connection while carrying the route is kept before the
	// route moves to an equivalent peer with a direct connection. A routing peer
	// that was never direct is kept for the same delay from when a direct peer
	// first contends for the route. Takes a duration ("30s", "0" to switch at
	// once) or "never" to only leave a peer that dropped from direct when it
	// disconnects; a peer that was never direct then uses the default delay.
	envRelayedSwitchDelay = "NB_HA_RELAYED_SWITCH_DELAY"

	relayedSwitchDelayNever = "never"

	// defaultRelayedSwitchDelay covers the common case of a direct connection
	// that drops to relay and recovers within seconds. Moving the route
	// resets every masqueraded flow using it, staying on the relay does not.
	defaultRelayedSwitchDelay = 30 * time.Second
)

// relayedSwitchPolicy is the resolved envRelayedSwitchDelay setting.
type relayedSwitchPolicy struct {
	delay time.Duration
	// never keeps a connected relayed routing peer regardless of delay
	never bool
}

func (p relayedSwitchPolicy) String() string {
	if p.never {
		return relayedSwitchDelayNever
	}
	return p.delay.String()
}

var (
	relayedSwitchOnce     sync.Once
	resolvedRelayedSwitch relayedSwitchPolicy
)

// relayedSwitch returns the process-wide relayed switch policy, read from the
// environment on first use.
func relayedSwitch() relayedSwitchPolicy {
	relayedSwitchOnce.Do(func() {
		resolvedRelayedSwitch = parseRelayedSwitchPolicy(os.Getenv(envRelayedSwitchDelay))
		log.Infof("routing peer relayed switch delay: %s", resolvedRelayedSwitch)
	})
	return resolvedRelayedSwitch
}

func parseRelayedSwitchPolicy(raw string) relayedSwitchPolicy {
	def := relayedSwitchPolicy{delay: defaultRelayedSwitchDelay}

	val := strings.TrimSpace(raw)
	if val == "" {
		return def
	}
	if strings.EqualFold(val, relayedSwitchDelayNever) {
		return relayedSwitchPolicy{never: true}
	}

	delay, err := time.ParseDuration(val)
	if err != nil || delay < 0 {
		log.Warnf("invalid %s value %q, using the default of %s: want a duration or %q",
			envRelayedSwitchDelay, raw, def, relayedSwitchDelayNever)
		return def
	}

	return relayedSwitchPolicy{delay: delay}
}
