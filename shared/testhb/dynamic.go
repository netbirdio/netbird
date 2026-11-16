package testhb

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// MetadataKey is the gRPC metadata key that carries the client schedule
	// on the Management Sync and Signal ConnectStream streams.
	MetadataKey = "x-nb-test-hb"
	// RelayQueryParam is the relay ws URL query parameter that carries the
	// client schedule.
	RelayQueryParam = "nbhb"

	// envMuteFile names a file with services to mute, one word per line.
	envMuteFile = "NB_TEST_HB_MUTE_FILE"
	// muteSignalBlackhole makes Signal drop every message to and from peers.
	muteSignalBlackhole = "signal-blackhole"
)

func (s Service) String() string {
	switch s {
	case ServiceManagement:
		return "management"
	case ServiceSignal:
		return "signal"
	case ServiceRelay:
		return "relay"
	default:
		return "unknown"
	}
}

// ClientSchedule is the heartbeat schedule a client sends when its stream
// opens: value "p=<phase ms>;period=<period s>;t=<client unix ms>".
// SkewMs is the server arrival time minus the client time, so it holds the
// clock difference plus the one-way delay.
type ClientSchedule struct {
	PhaseMs int64
	Period  time.Duration
	SkewMs  int64
	OK      bool
}

// ParseClientSchedule parses the client value. A bad or missing value gives
// OK=false. arrival is the server wall time when the stream opened.
func ParseClientSchedule(v string, arrival time.Time) ClientSchedule {
	var phase, period, t int64
	var havePhase, havePeriod, haveT bool
	for _, part := range strings.Split(strings.TrimSpace(v), ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ClientSchedule{}
		}
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return ClientSchedule{}
		}
		switch k {
		case "p":
			phase, havePhase = n, true
		case "period":
			period, havePeriod = n, true
		case "t":
			t, haveT = n, true
		}
	}
	if !havePhase || !havePeriod || !haveT || period <= 0 || t <= 0 || phase < 0 || phase >= period*1000 {
		return ClientSchedule{}
	}
	return ClientSchedule{
		PhaseMs: phase,
		Period:  time.Duration(period) * time.Second,
		SkewMs:  arrival.UnixMilli() - t,
		OK:      true,
	}
}

// ClientScheduleFor parses the client value for svc. arrival is the real
// wall time when the stream opened; the svc skew knob is added to it.
func ClientScheduleFor(svc Service, v string, arrival time.Time) ClientSchedule {
	return ParseClientSchedule(v, arrival.Add(skew(svc)))
}

// DynamicDelay returns the time from now until the first server wall time w,
// in whole ms and strictly after now, with (w - SkewMs) mod period == PhaseMs.
// now is the service wall clock. cs must be OK.
func DynamicDelay(cs ClientSchedule, now time.Time) time.Duration {
	p := cs.Period.Milliseconds()
	if p < 1 {
		p = 1
	}
	x := now.UnixMilli() - cs.SkewMs + 1 // first whole ms strictly after now, client clock
	x += ((cs.PhaseMs-x)%p + p) % p
	return time.UnixMilli(x + cs.SkewMs).Sub(now)
}

// LogSuffix returns " dyn=<phase ms>/<skew ms>" for the heartbeat log line in
// dynamic mode, else "".
func LogSuffix(mode Mode, cs ClientSchedule) string {
	if mode != ModeDynamic || !cs.OK {
		return ""
	}
	return fmt.Sprintf(" dyn=%d/%d", cs.PhaseMs, cs.SkewMs)
}

// skew returns NB_TEST_HB_SKEW_<SVC>_MS, which emulates a wrong server clock.
func skew(svc Service) time.Duration {
	n, err := strconv.ParseInt(os.Getenv("NB_TEST_HB_SKEW_"+strings.ToUpper(svc.String())+"_MS"), 10, 64)
	if err != nil {
		return 0
	}
	return time.Duration(n) * time.Millisecond
}

// Now returns the wall clock of svc: time.Now() plus its skew knob.
func Now(svc Service) time.Time {
	return time.Now().Add(skew(svc))
}

// muted reports whether word is a line in the NB_TEST_HB_MUTE_FILE file.
// A missing file mutes nothing.
func muted(word string) bool {
	path := os.Getenv(envMuteFile)
	if path == "" {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, w := range strings.Fields(string(b)) {
		if w == word {
			return true
		}
	}
	return false
}

// Muted reports whether svc must skip its heartbeat sends for this tick. The
// Signal blackhole mutes the Signal heartbeats too.
func Muted(svc Service) bool {
	if svc == ServiceSignal && muted(muteSignalBlackhole) {
		return true
	}
	return muted(svc.String())
}

// SignalBlackhole reports whether Signal must drop every message to and from
// peers while keeping their streams open.
func SignalBlackhole() bool {
	return muted(muteSignalBlackhole)
}
