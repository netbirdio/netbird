// Package testhb builds the test-only heartbeat schedule value the client sends
// when a Management, Signal or relay stream opens. It is off unless
// NB_TEST_HB_DYNAMIC is set.
package testhb

import (
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// MetadataKey is the gRPC metadata key for the Management Sync and Signal
	// ConnectStream streams.
	MetadataKey = "x-nb-test-hb"
	// RelayQueryParam is the relay ws URL query parameter.
	RelayQueryParam = "nbhb"

	// EnvDynamic switches the client value on.
	EnvDynamic = "NB_TEST_HB_DYNAMIC"
	// EnvPeriod is the heartbeat period in seconds, default 30.
	EnvPeriod = "NB_TEST_HB_PERIOD_SEC"
	// EnvPhase overrides the phase in ms.
	EnvPhase = "NB_TEST_HB_CLIENT_PHASE_MS"

	defaultPeriodSec = 30
)

var (
	ownKeyMu sync.Mutex
	ownKey   string
)

// SetOwnKey remembers the client public key for dialers that do not know it,
// such as the relay ws dialer.
func SetOwnKey(pubKey string) {
	ownKeyMu.Lock()
	ownKey = pubKey
	ownKeyMu.Unlock()
}

// OwnKey returns the key set by SetOwnKey.
func OwnKey() string {
	ownKeyMu.Lock()
	defer ownKeyMu.Unlock()
	return ownKey
}

// schedule is the parsed client heartbeat schedule.
type schedule struct {
	phaseMs   int64
	periodSec int64
}

// Value returns "p=<phase ms>;period=<period s>;t=<unix ms>" for svc, with t
// taken now, so call it right before the stream open. ok is false when the
// switch is off or no phase can be found; send nothing then. It reads the env
// on each call and logs the schedule.
func Value(svc, pubKey string) (string, bool) {
	s, ok := scheduleFromEnv(os.Getenv, pubKey)
	if !ok {
		return "", false
	}
	log.Infof("testhb: client schedule svc=%s p=%d period=%d", svc, s.phaseMs, s.periodSec)
	return s.value(time.Now()), true
}

func (s schedule) value(now time.Time) string {
	return fmt.Sprintf("p=%d;period=%d;t=%d", s.phaseMs, s.periodSec, now.UnixMilli())
}

func scheduleFromEnv(getenv func(string) string, pubKey string) (schedule, bool) {
	if !dynamicEnabled(getenv(EnvDynamic)) {
		return schedule{}, false
	}
	period := int64(defaultPeriodSec)
	if v := getenv(EnvPeriod); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			log.Warnf("invalid %s %q, using %d", EnvPeriod, v, defaultPeriodSec)
		} else {
			period = n
		}
	}
	periodMs := period * 1000

	if v := getenv(EnvPhase); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil && n >= 0 && n < periodMs {
			return schedule{phaseMs: n, periodSec: period}, true
		}
		log.Warnf("invalid %s %q, not in [0, %d)", EnvPhase, v, periodMs)
	}
	if pubKey == "" {
		log.Warnf("testhb: no public key for the client phase, sending no schedule")
		return schedule{}, false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(pubKey))
	return schedule{phaseMs: int64(h.Sum32()) % periodMs, periodSec: period}, true
}

func dynamicEnabled(v string) bool {
	if v == "" {
		return false
	}
	on, err := strconv.ParseBool(v)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvDynamic, err)
		return false
	}
	return on
}
