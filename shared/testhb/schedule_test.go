package testhb

import (
	"context"
	"hash/fnv"
	"strconv"
	"testing"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

func offsetOf(key string, p int64) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int64(h.Sum32()) % p
}

func TestFirstDelayAligned(t *testing.T) {
	period := 30 * time.Second
	keys := []string{PhaseKey("a"), PhaseKey("b"), PhaseKey("peer-xyz"), "plain"}
	nows := []time.Time{
		time.Unix(1700000000, 0),
		time.Unix(1700000000, 1),
		time.Unix(1700000017, 999999999),
		time.Unix(1700000029, 500000000),
		time.Unix(1762500000, 123456789),
	}
	for _, key := range keys {
		off := offsetOf(key, 30)
		for _, now := range nows {
			d := FirstDelay(ModeAligned, period, key, now)
			if d <= 0 || d > period {
				t.Fatalf("key %q now %v: delay %v out of (0, %v]", key, now, d, period)
			}
			fire := now.Add(d)
			if fire.Nanosecond() != 0 {
				t.Fatalf("key %q now %v: fire %v not on whole second", key, now, fire)
			}
			if fire.Unix()%30 != off {
				t.Fatalf("key %q now %v: fire unix%%30=%d want %d", key, now, fire.Unix()%30, off)
			}
		}
	}
}

func TestFirstDelaySameOffsetSameDelay(t *testing.T) {
	// find two different keys with the same offset
	base := "k0"
	want := offsetOf(base, 30)
	var other string
	for i := 1; i < 10000; i++ {
		k := "k" + strconv.Itoa(i)
		if offsetOf(k, 30) == want {
			other = k
			break
		}
	}
	if other == "" {
		t.Fatal("no key with same offset found")
	}
	now := time.Unix(1700000003, 250000000)
	if a, b := FirstDelay(ModeAligned, 30*time.Second, base, now), FirstDelay(ModeAligned, 30*time.Second, other, now); a != b {
		t.Fatalf("same offset, different delay: %v vs %v", a, b)
	}
}

func TestFirstDelayConnect(t *testing.T) {
	if d := FirstDelay(ModeConnect, 30*time.Second, "x", time.Now()); d != 30*time.Second {
		t.Fatalf("connect delay %v", d)
	}
}

func TestPhaseKey(t *testing.T) {
	k := "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eHF1dXg="
	if PhaseKey(k) != messages.HashID(k).String() {
		t.Fatal("PhaseKey mismatch")
	}
}

func TestParseEnv(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeOff, "bogus": ModeOff, "off": ModeOff, "connect": ModeConnect, "aligned": ModeAligned} {
		if got := parseMode(in); got != want {
			t.Fatalf("parseMode(%q)=%v want %v", in, got, want)
		}
	}
	for in, want := range map[string]time.Duration{"": defaultPeriod, "x": defaultPeriod, "-5": defaultPeriod, "0": defaultPeriod, "10": 10 * time.Second} {
		if got := parsePeriod(in); got != want {
			t.Fatalf("parsePeriod(%q)=%v want %v", in, got, want)
		}
	}
}

func TestTickerOff(t *testing.T) {
	t.Setenv("NB_TEST_HB_MODE", "")
	if ModeFromEnv() != ModeOff {
		t.Skip("env already loaded with non-off mode")
	}
	if Ticker(context.Background(), "x") != nil {
		t.Fatal("off ticker not nil")
	}
}

func TestTickerAlignedFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := startTicker(ctx, ModeAligned, time.Second, "x")
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("aligned ticker did not fire")
	}
}
