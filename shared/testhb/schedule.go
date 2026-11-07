// Package testhb schedules test-only server heartbeats. It is enabled only
// through NB_TEST_HB_* env vars and is off by default.
package testhb

import (
	"context"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

type Mode int

const (
	ModeOff Mode = iota
	ModeConnect
	ModeAligned
	ModeSpread
)

// Service picks the spread-mode offset: service i fires i*P/3 seconds after
// the aligned phase.
type Service int

const (
	ServiceManagement Service = iota
	ServiceSignal
	ServiceRelay
)

const (
	defaultPeriod = 30 * time.Second
	// envModeFile names a file that overrides NB_TEST_HB_MODE while the server
	// runs, so a test can switch modes without restarting the streams.
	envModeFile = "NB_TEST_HB_MODE_FILE"
	// offPoll is how often a paused ticker checks the mode file again.
	offPoll = time.Second
)

func (m Mode) String() string {
	switch m {
	case ModeConnect:
		return "connect"
	case ModeAligned:
		return "aligned"
	case ModeSpread:
		return "spread"
	default:
		return "off"
	}
}

var (
	envOnce   sync.Once
	envMode   Mode
	envPeriod time.Duration
)

func loadEnv() {
	envOnce.Do(func() {
		envMode = parseMode(os.Getenv("NB_TEST_HB_MODE"))
		envPeriod = parsePeriod(os.Getenv("NB_TEST_HB_PERIOD_SEC"))
	})
}

func parseMode(s string) Mode {
	switch s {
	case "connect":
		return ModeConnect
	case "aligned":
		return ModeAligned
	case "spread":
		return ModeSpread
	default:
		return ModeOff
	}
}

func parsePeriod(s string) time.Duration {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultPeriod
	}
	return time.Duration(n) * time.Second
}

func ModeFromEnv() Mode {
	loadEnv()
	return envMode
}

func PeriodFromEnv() time.Duration {
	loadEnv()
	return envPeriod
}

// CurrentMode returns the mode from the NB_TEST_HB_MODE_FILE file when it is
// set and readable, else ModeFromEnv(). It only matters when ModeFromEnv() is
// not off: an off server never starts tickers, so it stays stock.
func CurrentMode() Mode {
	path := os.Getenv(envModeFile)
	if path == "" {
		return ModeFromEnv()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ModeFromEnv()
	}
	return parseMode(strings.TrimSpace(string(b)))
}

// Enabled reports ModeFromEnv() != ModeOff.
func Enabled() bool {
	return ModeFromEnv() != ModeOff
}

// PhaseKey returns the key that all three servers use for one peer:
// the relay hashed peer ID string, messages.HashID(wgPubKeyBase64).String().
func PhaseKey(wgPubKeyBase64 string) string {
	return messages.HashID(wgPubKeyBase64).String()
}

// FirstDelay is pure and testable. Connect: period. Aligned: time until the
// next whole second where unix % periodSec == fnv32a(phaseKey) % periodSec
// (strictly after now). Spread: the same with target
// (fnv32a(phaseKey) + svc*periodSec/3) % periodSec. Only spread uses svc.
func FirstDelay(mode Mode, period time.Duration, phaseKey string, svc Service, now time.Time) time.Duration {
	if mode != ModeAligned && mode != ModeSpread {
		return period
	}
	p := int64(period / time.Second)
	if p < 1 {
		p = 1
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(phaseKey))
	offset := int64(h.Sum32()) % p
	if mode == ModeSpread {
		offset = (offset + int64(svc)*p/3) % p
	}

	s := now.Unix() + 1 // first whole second strictly after now
	s += ((offset-s%p)%p + p) % p
	return time.Unix(s, 0).Sub(now)
}

// Ticker returns a channel that fires on schedule until ctx is done.
// Off in the env: returns nil (a nil channel never fires in select).
// Otherwise the schedule follows CurrentMode() at each fire, so a mode file
// change takes effect within one period. Mode file off pauses the ticker.
// Aligned and spread: recompute each fire from wall clock, no drift.
func Ticker(ctx context.Context, phaseKey string, svc Service) <-chan time.Time {
	if ModeFromEnv() == ModeOff {
		return nil
	}
	return startTicker(ctx, CurrentMode, PeriodFromEnv(), phaseKey, svc)
}

func nextDelay(mode Mode, period time.Duration, phaseKey string, svc Service, now time.Time) time.Duration {
	switch mode {
	case ModeOff:
		return offPoll
	case ModeConnect:
		return period
	default:
		return FirstDelay(mode, period, phaseKey, svc, now)
	}
}

func startTicker(ctx context.Context, mode func() Mode, period time.Duration, phaseKey string, svc Service) <-chan time.Time {
	ch := make(chan time.Time, 1)
	send := func(t time.Time) {
		select {
		case ch <- t:
		default: // reader is slow, drop this tick
		}
	}

	go func() {
		t := time.NewTimer(time.Hour)
		defer t.Stop()
		for {
			m := mode()
			t.Reset(nextDelay(m, period, phaseKey, svc, time.Now()))
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				// A tick scheduled under the old mode is dropped after a switch.
				if m != ModeOff && mode() == m {
					send(now)
				}
			}
		}
	}()
	return ch
}
