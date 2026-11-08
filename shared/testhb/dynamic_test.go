package testhb

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClientSchedule(t *testing.T) {
	arrival := time.UnixMilli(1762600000500)
	tests := []struct {
		name string
		in   string
		want ClientSchedule
	}{
		{"contract example", "p=17342;period=30;t=1762600000123", ClientSchedule{PhaseMs: 17342, Period: 30 * time.Second, SkewMs: 377, OK: true}},
		{"any order", "t=1762600000123;period=30;p=0", ClientSchedule{PhaseMs: 0, Period: 30 * time.Second, SkewMs: 377, OK: true}},
		{"client ahead gives negative skew", "p=5;period=10;t=1762600002500", ClientSchedule{PhaseMs: 5, Period: 10 * time.Second, SkewMs: -2000, OK: true}},
		{"last phase ms", "p=29999;period=30;t=1762600000500", ClientSchedule{PhaseMs: 29999, Period: 30 * time.Second, SkewMs: 0, OK: true}},
		{"phase equals period", "p=30000;period=30;t=1762600000123", ClientSchedule{}},
		{"negative phase", "p=-1;period=30;t=1762600000123", ClientSchedule{}},
		{"zero period", "p=0;period=0;t=1762600000123", ClientSchedule{}},
		{"missing t", "p=1;period=30", ClientSchedule{}},
		{"missing phase", "period=30;t=1762600000123", ClientSchedule{}},
		{"not a number", "p=x;period=30;t=1762600000123", ClientSchedule{}},
		{"no equals", "p=1;period;t=1762600000123", ClientSchedule{}},
		{"empty", "", ClientSchedule{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseClientSchedule(tc.in, arrival), "value %q", tc.in)
		})
	}
}

func TestDynamicDelay(t *testing.T) {
	tests := []struct {
		name string
		cs   ClientSchedule
		now  time.Time
	}{
		{"zero skew", ClientSchedule{PhaseMs: 17342, Period: 30 * time.Second}, time.UnixMilli(1762600000123)},
		{"positive skew", ClientSchedule{PhaseMs: 17342, Period: 30 * time.Second, SkewMs: 377}, time.UnixMilli(1762600000123)},
		{"negative skew", ClientSchedule{PhaseMs: 100, Period: 30 * time.Second, SkewMs: -4321}, time.Unix(1762600000, 999999999)},
		{"skew above one period", ClientSchedule{PhaseMs: 2500, Period: 10 * time.Second, SkewMs: 73456}, time.UnixMilli(1762600000000)},
		{"negative skew above one period", ClientSchedule{PhaseMs: 9999, Period: 10 * time.Second, SkewMs: -95001}, time.UnixMilli(1762600000000).Add(300 * time.Microsecond)},
		{"client period 5s", ClientSchedule{PhaseMs: 4000, Period: 5 * time.Second, SkewMs: 12}, time.UnixMilli(1762600001234)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := tc.cs
			cs.OK = true
			d := DynamicDelay(cs, tc.now)
			fire := tc.now.Add(d)
			p := cs.Period.Milliseconds()
			assert.Greater(t, d, time.Duration(0), "fire must be strictly after now")
			assert.LessOrEqual(t, d, cs.Period, "fire must be within one client period")
			assert.Zero(t, fire.Nanosecond()%int(time.Millisecond), "fire %v not on a whole ms", fire)
			got := ((fire.UnixMilli()-cs.SkewMs)%p + p) % p
			assert.Equal(t, cs.PhaseMs, got, "client-clock phase of fire %v", fire)
		})
	}
}

func TestDynamicDelayStrictlyAfterNow(t *testing.T) {
	cs := ClientSchedule{PhaseMs: 1000, Period: 30 * time.Second, SkewMs: 500, OK: true}
	// now is exactly on the target ms: the next fire is one full period later.
	now := time.UnixMilli(1762600000000 + 1000 + 500 - 1762600000000%30000)
	require.Equal(t, int64(1000), ((now.UnixMilli()-500)%30000+30000)%30000, "test setup")
	assert.Equal(t, 30*time.Second, DynamicDelay(cs, now), "fire on now must move to the next period")
}

// The skew knob emulates a wrong server clock. It must move the aligned fire
// on the real clock, but not the dynamic one: the arrival time carries the
// same error, so it cancels out.
func TestSkewKnobShiftsAlignedNotDynamic(t *testing.T) {
	const svc = ServiceSignal
	real := time.UnixMilli(1762600000123)
	clientT := real.UnixMilli() - 40 // 40 ms one-way delay, synced clocks
	value := "p=17342;period=30;t=" + strconv.FormatInt(clientT, 10)

	landing := func(mode Mode) time.Time {
		cs := ClientScheduleFor(svc, value, real)
		require.True(t, cs.OK)
		d, active := nextDelay(mode, 30*time.Second, "x", svc, cs, real.Add(skew(svc)))
		require.True(t, active)
		return real.Add(d)
	}

	t.Setenv("NB_TEST_HB_SKEW_SIGNAL_MS", "0")
	alignedBase, dynBase := landing(ModeAligned), landing(ModeDynamic)

	t.Setenv("NB_TEST_HB_SKEW_SIGNAL_MS", "7250")
	assert.Equal(t, 7250*time.Millisecond, Now(svc).Sub(time.Now()).Round(time.Second/4), "Now must include the knob")
	aligned, dyn := landing(ModeAligned), landing(ModeDynamic)

	shift := ((alignedBase.Sub(aligned) % (30 * time.Second)) + 30*time.Second) % (30 * time.Second)
	assert.Equal(t, 7250*time.Millisecond, shift, "aligned fire must move back by the knob")
	assert.Equal(t, dynBase, dyn, "dynamic fire must not move with the knob")
	assert.Equal(t, int64(17342), (dyn.UnixMilli()-40)%30000, "dynamic fire must land on the client phase plus the one-way delay")

	// Another service is not affected.
	assert.Zero(t, skew(ServiceManagement), "management skew")
}

func TestDynamicNeedsClientSchedule(t *testing.T) {
	_, active := nextDelay(ModeDynamic, 30*time.Second, "x", ServiceRelay, ClientSchedule{}, time.Now())
	assert.False(t, active, "dynamic without a client value must not send")
	_, active = nextDelay(ModeAligned, 30*time.Second, "x", ServiceRelay, ClientSchedule{}, time.Now())
	assert.True(t, active, "aligned must not need a client value")
}

func TestTickerDynamicFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Fire when (w + 300) mod 2000 == 700, that is w mod 2000 == 400.
	cs := ClientSchedule{PhaseMs: 700, Period: 2 * time.Second, SkewMs: -300, OK: true}
	ch := startTicker(ctx, fixed(ModeDynamic), 30*time.Second, "x", ServiceSignal, cs)
	for i := 0; i < 2; i++ {
		select {
		case now := <-ch:
			got := now.UnixMilli() % 2000
			assert.True(t, got >= 400 && got < 460, "tick %d at ms %d mod 2000, want 400", i, got)
		case <-time.After(3 * time.Second):
			t.Fatalf("dynamic ticker did not fire, tick %d", i)
		}
	}
}

func TestTickerDynamicWithoutValueSilent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := startTicker(ctx, fixed(ModeDynamic), time.Second, "x", ServiceSignal, ClientSchedule{})
	select {
	case <-ch:
		t.Fatal("dynamic ticker without a client value fired")
	case <-time.After(2500 * time.Millisecond):
	}
}

// A live switch between aligned and dynamic must follow the mode file.
func TestTickerSwitchAlignedDynamic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cur atomic.Int32
	cur.Store(int32(ModeAligned))
	cs := ClientSchedule{PhaseMs: 1500, Period: 3 * time.Second, OK: true}
	ch := startTicker(ctx, func() Mode { return Mode(cur.Load()) }, 3*time.Second, "x", ServiceRelay, cs)

	select {
	case now := <-ch:
		assert.Equal(t, offsetOf("x", 3), now.Round(time.Second).Unix()%3, "aligned tick phase")
	case <-time.After(5 * time.Second):
		t.Fatal("aligned ticker did not fire")
	}

	cur.Store(int32(ModeDynamic))
	deadline := time.After(8 * time.Second)
	for {
		select {
		case now := <-ch:
			got := now.UnixMilli() % 3000
			if got >= 1500 && got < 1560 {
				return
			}
			// At most one tick planned under aligned may still arrive.
			assert.Less(t, got%1000, int64(60), "unexpected tick at ms %d mod 3000", got)
		case <-deadline:
			t.Fatal("no dynamic tick after the switch")
		}
	}
}

func TestMuteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mute")
	t.Setenv(envMuteFile, path)
	assert.False(t, Muted(ServiceRelay), "missing file must mute nothing")

	require.NoError(t, os.WriteFile(path, []byte("relay\nsignal-blackhole\n"), 0o644))
	assert.True(t, Muted(ServiceRelay), "relay listed")
	assert.True(t, Muted(ServiceSignal), "signal-blackhole must mute signal heartbeats too")
	assert.False(t, Muted(ServiceManagement), "management not listed")
	assert.True(t, SignalBlackhole(), "blackhole listed")

	require.NoError(t, os.WriteFile(path, []byte(""), 0o644))
	assert.False(t, Muted(ServiceRelay), "empty file mutes nothing")
	assert.False(t, SignalBlackhole(), "empty file has no blackhole")
}

func TestLogSuffix(t *testing.T) {
	cs := ClientSchedule{PhaseMs: 17342, SkewMs: -12, Period: 30 * time.Second, OK: true}
	assert.Equal(t, " dyn=17342/-12", LogSuffix(ModeDynamic, cs), "dynamic suffix")
	assert.Equal(t, "", LogSuffix(ModeAligned, cs), "aligned has no suffix")
	assert.Equal(t, "", LogSuffix(ModeDynamic, ClientSchedule{}), "no client value has no suffix")
}

func TestParseModeDynamic(t *testing.T) {
	assert.Equal(t, ModeDynamic, parseMode("dynamic"), "parse")
	assert.Equal(t, "dynamic", ModeDynamic.String(), "string")
}
