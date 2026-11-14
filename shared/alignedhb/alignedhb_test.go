package alignedhb

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestStreamRequestRoundTrip(t *testing.T) {
	plain := StreamRequest{Period: 60 * time.Second}
	assert.Equal(t, "period=60", plain.Value())
	got, err := ParseStreamRequest(plain.Value())
	require.NoError(t, err)
	assert.Equal(t, plain, got)

	signed := StreamRequest{
		Period: 60 * time.Second,
		Signed: &SignedPhase{Phase: 12345 * time.Millisecond, Day: 20405, Signature: []byte{1, 2, 3, 4}},
	}
	assert.Equal(t, "period=60;phase=12345;day=20405;sig=AQIDBA==", signed.Value())
	got, err = ParseStreamRequest(signed.Value())
	require.NoError(t, err)
	assert.Equal(t, signed, got)
}

func TestParseStreamRequestRejects(t *testing.T) {
	for name, v := range map[string]string{
		"empty":            "",
		"no period":        "phase=1;day=1;sig=AQ==",
		"zero period":      "period=0",
		"negative period":  "period=-1",
		"period too big":   "period=65536",
		"period not int":   "period=1.5",
		"duplicate":        "period=60;period=30",
		"malformed":        "period=60;phase",
		"empty key":        "period=60;=5",
		"trailing sep":     "period=60;",
		"phase only":       "period=60;phase=5",
		"no sig":           "period=60;phase=5;day=1",
		"phase at period":  "period=60;phase=60000;day=1;sig=AQ==",
		"negative day":     "period=60;phase=5;day=-1;sig=AQ==",
		"bad base64":       "period=60;phase=5;day=1;sig=%%%",
		"empty sig":        "period=60;phase=5;day=1;sig=",
		"sig too long":     "period=60;phase=5;day=1;sig=" + strings.Repeat("A", 100),
		"value too long":   "period=60;x=" + strings.Repeat("a", maxValueLen),
		"phase not number": "period=60;phase=x;day=1;sig=AQ==",
	} {
		_, err := ParseStreamRequest(v)
		assert.Error(t, err, "case %q: %q", name, v)
	}
}

func TestParseStreamRequestIgnoresUnknownKeys(t *testing.T) {
	got, err := ParseStreamRequest("period=60;future=1")
	require.NoError(t, err)
	assert.Equal(t, StreamRequest{Period: 60 * time.Second}, got)
}

func TestAnswerRoundTrip(t *testing.T) {
	a := Answer{Period: 60 * time.Second, Phase: 4321 * time.Millisecond}
	assert.Equal(t, "period=60;phase=4321", a.Value())
	got, err := parseAnswer(a.Value())
	require.NoError(t, err)
	assert.Equal(t, a, got)

	for _, v := range []string{"", "period=60", "phase=1", "period=60;phase=60000", "period=0;phase=0"} {
		_, err := parseAnswer(v)
		assert.Error(t, err, "value %q", v)
	}
}

func FuzzParseStreamRequest(f *testing.F) {
	f.Add("period=60")
	f.Add("period=60;phase=12345;day=20405;sig=AQIDBA==")
	f.Add("period=60;phase=5")
	f.Add(";;==")
	f.Fuzz(func(t *testing.T, v string) {
		r, err := ParseStreamRequest(v)
		if err != nil {
			return
		}
		require.Positive(t, r.Period)
		if r.Signed != nil {
			require.True(t, ValidPhase(r.Signed.Phase, r.Period), "phase %s period %s", r.Signed.Phase, r.Period)
			require.NotEmpty(t, r.Signed.Signature)
			require.LessOrEqual(t, len(r.Signed.Signature), MaxSignatureLen)
		}
		again, err := ParseStreamRequest(r.Value())
		require.NoError(t, err, "re-encoded value %q", r.Value())
		require.Equal(t, r, again)
	})
}

func TestNextDelay(t *testing.T) {
	period := 60 * time.Second
	base := time.UnixMilli(1_700_000_040_000) // offset 0 inside a 60 s period

	assert.Equal(t, 5*time.Second, NextDelay(period, 5*time.Second, base))
	assert.Equal(t, period, NextDelay(period, 0, base), "a fire exactly now moves to the next period")
	assert.Equal(t, 500*time.Microsecond, NextDelay(period, time.Second, base.Add(999500*time.Microsecond)))
	assert.Equal(t, 59*time.Second, NextDelay(period, 0, base.Add(time.Second)))
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
			assert.InDelta(t, period.Milliseconds(), f.Sub(fires[i-1]).Milliseconds(), 30, "fire %d spacing", i)
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

func TestStreamAnswerWithoutPhase(t *testing.T) {
	v := PendingAnswerValue(60 * time.Second)
	assert.Equal(t, "period=60", v)
	a, aligned, err := ParseStreamAnswer(v)
	require.NoError(t, err)
	assert.False(t, aligned, "no phase: the stream stays stock")
	assert.Equal(t, 60*time.Second, a.Period, "period")
	_, err = parseAnswer(v)
	assert.Error(t, err, "parseAnswer needs the phase")

	full := Answer{Period: 60 * time.Second, Phase: 1234 * time.Millisecond}
	a, aligned, err = ParseStreamAnswer(full.Value())
	require.NoError(t, err)
	assert.True(t, aligned, "with the phase the stream is aligned")
	assert.Equal(t, full, a)

	_, _, err = ParseStreamAnswer("period=60;phase=60000")
	assert.Error(t, err, "phase outside the period")
	_, _, err = ParseStreamAnswer("phase=1")
	assert.Error(t, err, "period missing")
}

func TestReceiveTimeoutAndKeepAliveIdle(t *testing.T) {
	if got := ReceiveTimeout(time.Minute); got != 70*time.Second {
		t.Errorf("ReceiveTimeout(60s) = %s, want 70s", got)
	}
	if got := TCPKeepAliveIdle(time.Minute); got != 2*time.Minute {
		t.Errorf("TCPKeepAliveIdle(60s) = %s, want 2m", got)
	}
}

// parseAnswer parses a value written by Answer.Value and requires the phase.
func parseAnswer(v string) (Answer, error) {
	a, aligned, err := ParseStreamAnswer(v)
	if err != nil {
		return Answer{}, err
	}
	if !aligned {
		return Answer{}, fmt.Errorf("%s: %w", keyPhase, errMissingField)
	}
	return a, nil
}
