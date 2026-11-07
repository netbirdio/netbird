// Package testhb schedules test-only server heartbeats. It is enabled only
// through NB_TEST_HB_* env vars and is off by default.
package testhb

import (
	"context"
	"hash/fnv"
	"os"
	"strconv"
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

const defaultPeriod = 30 * time.Second

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
// Off: returns nil (a nil channel never fires in select).
// Aligned and spread: recompute each fire from wall clock, no drift.
func Ticker(ctx context.Context, phaseKey string, svc Service) <-chan time.Time {
	mode := ModeFromEnv()
	if mode == ModeOff {
		return nil
	}
	return startTicker(ctx, mode, PeriodFromEnv(), phaseKey, svc)
}

func startTicker(ctx context.Context, mode Mode, period time.Duration, phaseKey string, svc Service) <-chan time.Time {
	ch := make(chan time.Time, 1)
	send := func(t time.Time) {
		select {
		case ch <- t:
		default: // reader is slow, drop this tick
		}
	}

	go func() {
		if mode == ModeConnect {
			t := time.NewTicker(period)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					send(now)
				}
			}
		}

		t := time.NewTimer(FirstDelay(mode, period, phaseKey, svc, time.Now()))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				send(now)
				t.Reset(FirstDelay(mode, period, phaseKey, svc, time.Now()))
			}
		}
	}()
	return ch
}
