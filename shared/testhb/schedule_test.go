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
			d := FirstDelay(ModeAligned, period, key, ServiceRelay, now)
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
	if a, b := FirstDelay(ModeAligned, 30*time.Second, base, ServiceManagement, now), FirstDelay(ModeAligned, 30*time.Second, other, ServiceSignal, now); a != b {
		t.Fatalf("same offset, different delay: %v vs %v", a, b)
	}
}

func TestFirstDelayConnect(t *testing.T) {
	for _, svc := range []Service{ServiceManagement, ServiceSignal, ServiceRelay} {
		if d := FirstDelay(ModeConnect, 30*time.Second, "x", svc, time.Now()); d != 30*time.Second {
			t.Fatalf("connect delay %v", d)
		}
	}
}

func TestPhaseKey(t *testing.T) {
	k := "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eHF1dXg="
	if PhaseKey(k) != messages.HashID(k).String() {
		t.Fatal("PhaseKey mismatch")
	}
}

func TestParseEnv(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeOff, "bogus": ModeOff, "off": ModeOff, "connect": ModeConnect, "aligned": ModeAligned, "spread": ModeSpread} {
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
	if Ticker(context.Background(), "x", ServiceSignal) != nil {
		t.Fatal("off ticker not nil")
	}
}

func TestTickerAlignedFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := startTicker(ctx, ModeAligned, time.Second, "x", ServiceManagement)
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("aligned ticker did not fire")
	}
}

var allServices = []Service{ServiceManagement, ServiceSignal, ServiceRelay}

func TestFirstDelaySpread(t *testing.T) {
	keys := []string{PhaseKey("a"), PhaseKey("peer-xyz"), "plain"}
	nows := []time.Time{
		time.Unix(1700000000, 0),
		time.Unix(1700000017, 999999999),
		time.Unix(1762500000, 123456789),
	}
	for _, ps := range []int64{30, 25, 10} {
		period := time.Duration(ps) * time.Second
		for _, key := range keys {
			h := offsetOf(key, ps)
			for _, now := range nows {
				for _, svc := range allServices {
					d := FirstDelay(ModeSpread, period, key, svc, now)
					if d <= 0 || d > period {
						t.Fatalf("p %d key %q svc %d: delay %v out of (0, %v]", ps, key, svc, d, period)
					}
					fire := now.Add(d)
					if fire.Nanosecond() != 0 {
						t.Fatalf("p %d key %q svc %d: fire %v not on whole second", ps, key, svc, fire)
					}
					want := (h + int64(svc)*ps/3) % ps
					if fire.Unix()%ps != want {
						t.Fatalf("p %d key %q svc %d: unix%%p=%d want %d", ps, key, svc, fire.Unix()%ps, want)
					}
				}
			}
		}
	}
}

func TestSpreadServicesThirdApart(t *testing.T) {
	for _, ps := range []int64{30, 25, 10} {
		period := time.Duration(ps) * time.Second
		third := ps / 3
		for _, key := range []string{PhaseKey("a"), PhaseKey("b"), "plain"} {
			// Phases relative to the management phase, mod P.
			now := time.Unix(1762500000, 0)
			base := now.Add(FirstDelay(ModeSpread, period, key, ServiceManagement, now)).Unix() % ps
			for i, svc := range allServices {
				ph := now.Add(FirstDelay(ModeSpread, period, key, svc, now)).Unix() % ps
				if dist := ((ph-base)%ps + ps) % ps; dist != int64(i)*third {
					t.Fatalf("p %d key %q svc %d: distance %d want %d", ps, key, svc, dist, int64(i)*third)
				}
			}
		}
	}
}

func TestSpreadIPhoneKey(t *testing.T) {
	const key = "sha-+RKfBlqPPJWW0GF/KUuTO+tBU384VR0wwzh0jWXaxh0="
	if h := offsetOf(key, 30); h != 23 {
		t.Fatalf("h=%d want 23", h)
	}
	now := time.Unix(1762500000, 500000000)
	want := map[Service]int64{ServiceManagement: 23, ServiceSignal: 3, ServiceRelay: 13}
	for svc, w := range want {
		fire := now.Add(FirstDelay(ModeSpread, 30*time.Second, key, svc, now))
		if fire.Unix()%30 != w {
			t.Fatalf("svc %d: unix%%30=%d want %d", svc, fire.Unix()%30, w)
		}
	}
	// Aligned ignores svc and keeps the shared phase.
	for _, svc := range allServices {
		fire := now.Add(FirstDelay(ModeAligned, 30*time.Second, key, svc, now))
		if fire.Unix()%30 != 23 {
			t.Fatalf("aligned svc %d: unix%%30=%d want 23", svc, fire.Unix()%30)
		}
	}
}

func TestTickerSpreadFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := startTicker(ctx, ModeSpread, 3*time.Second, "x", ServiceRelay)
	select {
	case now := <-ch:
		// The timer can fire a few microseconds before the wall-clock second.
		if got, want := now.Round(time.Second).Unix()%3, (offsetOf("x", 3)+2)%3; got != want {
			t.Fatalf("spread tick unix%%3=%d want %d", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("spread ticker did not fire")
	}
}

func TestModeString(t *testing.T) {
	for m, want := range map[Mode]string{ModeOff: "off", ModeConnect: "connect", ModeAligned: "aligned", ModeSpread: "spread"} {
		if m.String() != want {
			t.Fatalf("%d.String()=%q want %q", m, m.String(), want)
		}
	}
}
