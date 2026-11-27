package alignedhb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestSupportedOnlyOnMobile(t *testing.T) {
	for goos, want := range map[string]bool{
		"ios": true, "android": true,
		"darwin": false, "linux": false, "windows": false, "freebsd": false, "js": false,
	} {
		assert.Equal(t, want, supportedOn(goos), "goos %s", goos)
	}
}

func TestPeriodSeconds(t *testing.T) {
	assert.Equal(t, uint32(60), PeriodSeconds(60*time.Second))
	assert.Equal(t, uint32(60), PeriodSeconds(60*time.Second+999*time.Millisecond), "rounds down")
	assert.Equal(t, uint32(0), PeriodSeconds(-time.Second))
	assert.Equal(t, ^uint32(0), PeriodSeconds(time.Duration(1<<62)), "saturates")
}

func TestClampPeriod(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0:                 MinPeriod,
		-time.Second:      MinPeriod,
		29 * time.Second:  MinPeriod,
		30 * time.Second:  MinPeriod,
		60 * time.Second:  60 * time.Second,
		300 * time.Second: MaxPeriod,
		301 * time.Second: MaxPeriod,
		time.Hour:         MaxPeriod,
	} {
		assert.Equal(t, want, ClampPeriod(in), "period %s", in)
	}
}

// TestPhaseSharedVector pins the phase every side must derive for one peer.
// The want values were computed from the contract formula with an independent
// SHA-256 tool, not from this package.
func TestPhaseSharedVector(t *testing.T) {
	peer := messages.HashID("test-key-1")
	assert.Equal(t, 43819*time.Millisecond, Phase(peer, 60*time.Second))
	assert.Equal(t, 13819*time.Millisecond, Phase(peer, 30*time.Second))

	other := messages.HashID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	assert.Equal(t, 57888*time.Millisecond, Phase(other, 60*time.Second))
	assert.NotEqual(t, Phase(peer, 60*time.Second), Phase(other, 60*time.Second))
}

func TestPhaseBounds(t *testing.T) {
	peer := messages.HashID("test-key-1")
	for _, period := range []time.Duration{30 * time.Second, 60 * time.Second, 300 * time.Second, time.Second, time.Millisecond} {
		phase := Phase(peer, period)
		assert.GreaterOrEqual(t, phase, time.Duration(0), "period %s", period)
		assert.Less(t, phase, period, "period %s", period)
		assert.Zero(t, phase%time.Millisecond, "whole milliseconds, period %s", period)
	}
	assert.Zero(t, Phase(peer, 0), "zero period")
	assert.Zero(t, Phase(peer, 500*time.Microsecond), "sub-millisecond period")
}

func TestMetadataValueRoundTrip(t *testing.T) {
	v := MetadataValue(60 * time.Second)
	assert.Equal(t, "period=60", v)
	got, err := ParseMetadataValue(v)
	require.NoError(t, err)
	assert.Equal(t, 60*time.Second, got)
}

// TestParseMetadataValueIgnoresLaterFields covers the contract rule that
// fields after the period and ";" are ignored, room for a later release.
func TestParseMetadataValueIgnoresLaterFields(t *testing.T) {
	for _, v := range []string{"period=60;", "period=60;phase=1", "period=60;period=30", "period=60;;x=" + strings.Repeat("9", 4096)} {
		got, err := ParseMetadataValue(v)
		require.NoError(t, err, v)
		assert.Equal(t, 60*time.Second, got, v)
	}
}

// TestParseMetadataValueRejects covers the contract rule that any value other
// than "period=<s>" leaves the stream stock.
func TestParseMetadataValueRejects(t *testing.T) {
	for name, v := range map[string]string{
		"empty":           "",
		"no period":       "phase=1",
		"zero period":     "period=0",
		"negative period": "period=-1",
		"signed period":   "period=+60",
		"period too big":  "period=65536",
		"period not int":  "period=1.5",
		"empty period":    "period=",
		"other text":      "period=60x",
		"bad period, sep": "period=60x;phase=1",
		"empty, sep":      "period=;phase=1",
		"space":           "period= 60",
		"space before ;":  "period=60 ;phase=1",
		"upper case key":  "PERIOD=60",
		"very long":       "period=" + strings.Repeat("9", 4096),
	} {
		_, err := ParseMetadataValue(v)
		assert.Error(t, err, "case %q: %q", name, v)
	}
}

func TestParseMetadataValueDoesNotClamp(t *testing.T) {
	got, err := ParseMetadataValue("period=5")
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, got, "clamping is the caller's job")
	assert.Equal(t, MinPeriod, ClampPeriod(got))
}

func TestNextDelay(t *testing.T) {
	period := 60 * time.Second
	base := time.UnixMilli(1_700_000_040_000) // offset 0 inside a 60 s period

	assert.Equal(t, 5*time.Second, NextDelay(period, 5*time.Second, base))
	assert.Equal(t, period, NextDelay(period, 0, base), "a fire exactly now moves to the next period")
	assert.Equal(t, 500*time.Microsecond, NextDelay(period, time.Second, base.Add(999500*time.Microsecond)))
	assert.Equal(t, 59*time.Second, NextDelay(period, 0, base.Add(time.Second)))
	assert.Equal(t, time.Millisecond, NextDelay(0, 0, base), "sub-millisecond period cannot divide by zero")
}

func TestTickerFiresOnPhase(t *testing.T) {
	period := 200 * time.Millisecond
	phase := 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tick := Ticker(ctx, period, phase, time.Now)
	var fires []time.Time
	for len(fires) < 3 {
		select {
		case f := <-tick:
			fires = append(fires, f)
		case <-time.After(2 * time.Second):
			t.Fatal("ticker did not fire")
		}
	}
	for i, f := range fires {
		off := time.Duration(f.UnixMilli()%period.Milliseconds()) * time.Millisecond
		assert.InDelta(t, phase.Milliseconds(), off.Milliseconds(), 30, "fire %d offset %s", i, off)
		if i > 0 {
			// A slow reader can lose a tick, so a gap of whole periods is fine.
			gap := f.Sub(fires[i-1])
			slots := int64((gap + period/2) / period)
			assert.GreaterOrEqual(t, slots, int64(1), "fire %d came less than a period after the last", i)
			assert.InDelta(t, slots*period.Milliseconds(), gap.Milliseconds(), 30, "fire %d spacing %s", i, gap)
		}
	}
}

func TestTickerStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tick := Ticker(ctx, 50*time.Millisecond, 0, time.Now)
	cancel()
	// Drain a fire that may have raced the cancel, then expect silence.
	select {
	case <-tick:
	case <-time.After(60 * time.Millisecond):
	}
	select {
	case <-tick:
		t.Fatal("ticker fired after cancel")
	case <-time.After(150 * time.Millisecond):
	}
}

// TestNextFireOnWallClock covers the slot choice after a fire. A wall clock
// stepped back must not pick the fired slot again; a long step back restarts
// from the wall clock instead of pausing for the whole step.
func TestNextFireOnWallClock(t *testing.T) {
	period := 60 * time.Second
	phase := 5 * time.Second
	slot := time.UnixMilli(1_700_000_045_000) // offset 5 s inside a 60 s period

	assert.Equal(t, slot.Add(period), nextFire(period, phase, slot, slot.Add(-3*time.Millisecond)),
		"a timer that fires early must move to the next slot")
	assert.Equal(t, slot.Add(period), nextFire(period, phase, slot, slot.Add(2*time.Millisecond)),
		"a fire on time must move to the next slot")
	assert.Equal(t, slot.Add(period), nextFire(period, phase, slot, slot.Add(-5*time.Second)),
		"a wall clock stepped back must not fire the same slot again")
	assert.Equal(t, slot.Add(-period), nextFire(period, phase, slot, slot.Add(-90*time.Second)),
		"a step back of over a period must restart from the wall clock")
	assert.Equal(t, slot.Add(2*period), nextFire(period, phase, slot, slot.Add(period+time.Second)),
		"a wall clock stepped forward must skip the passed slots")
}

// TestTickerKeepsOneTickForLateReader covers the one-tick buffer: a reader
// that was busy over a fire must still get that tick, and only one.
func TestTickerKeepsOneTickForLateReader(t *testing.T) {
	period := 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tick := Ticker(ctx, period, 0, time.Now)
	// Read in the middle of a period after at least two fires, so a late
	// fire before the read and the next fire after it are both far away.
	time.Sleep(NextDelay(period, 0, time.Now()) + 2*period + period/2)

	select {
	case <-tick:
	default:
		t.Fatal("a tick that fired while the reader was busy must wait for it")
	}
	// The window ends before the next slot, so only a queued tick can
	// arrive in it. It is computed after the read, as the sleep may overshoot.
	select {
	case <-tick:
		t.Fatal("only one unread tick must wait, the later ones are dropped")
	case <-time.After(NextDelay(period, 0, time.Now()) / 2):
	}
}

func TestReceiveTimeoutAndKeepAliveIdle(t *testing.T) {
	assert.Equal(t, 70*time.Second, ReceiveTimeout(time.Minute))
	assert.Equal(t, 2*time.Minute, TCPKeepAliveIdle(time.Minute))
}
