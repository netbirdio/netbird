package server

import (
	"context"
	"math"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestParseRate(t *testing.T) {
	tests := []struct {
		spec    string
		want    rate.Limit
		wantErr bool
	}{
		{spec: "", want: rate.Inf},
		{spec: "0", want: rate.Inf},
		{spec: "off", want: rate.Inf},
		{spec: "unlimited", want: rate.Inf},
		{spec: "50mbps", want: 50e6 / 8},
		{spec: "50Mbit/s", want: 50e6 / 8},
		{spec: "6.25MB/s", want: 6.25e6},
		{spec: "100kbps", want: 100e3 / 8},
		{spec: "1gbps", want: 1e9 / 8},
		{spec: "1048576", want: 1048576},
		{spec: "-1mbps", wantErr: true},
		{spec: "fast", wantErr: true},
	}

	for _, tc := range tests {
		got, err := parseRate(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseRate(%q) expected error", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRate(%q): %v", tc.spec, err)
			continue
		}
		if math.Abs(float64(got-tc.want)) > 1 {
			t.Errorf("parseRate(%q) = %v, want %v", tc.spec, got, tc.want)
		}
	}
}

func TestParsePeerIDKey(t *testing.T) {
	pubKey := "abcdEFGH1234567890+/publickey="
	want := messages.HashID(pubKey)

	got, err := parsePeerIDKey(pubKey)
	if err != nil {
		t.Fatalf("parsePeerIDKey(pubkey): %v", err)
	}
	if got != want {
		t.Fatalf("parsePeerIDKey(pubkey) = %v, want %v", got, want)
	}

	got, err = parsePeerIDKey(want.String())
	if err != nil {
		t.Fatalf("parsePeerIDKey(relay id): %v", err)
	}
	if got != want {
		t.Fatalf("parsePeerIDKey(relay id) = %v, want %v", got, want)
	}

	if _, err := parsePeerIDKey(""); err == nil {
		t.Fatal("expected error for empty key")
	}
	if _, err := parsePeerIDKey("sha-notbase64!"); err == nil {
		t.Fatal("expected error for invalid relay id")
	}
}

func TestLimiterSet(t *testing.T) {
	disabled, err := newLimiterSet(RateLimitConfig{Default: "50mbps", Peers: map[string]string{"a": "1mbps"}})
	if err != nil {
		t.Fatalf("newLimiterSet disabled: %v", err)
	}
	if got := disabled.forDst(messages.HashID("peer")); got != nil {
		t.Fatalf("disabled limiter set returned %v", got)
	}

	pubKey := "peer-public-key"
	limited, err := newLimiterSet(RateLimitConfig{
		Enabled: true,
		Default: "50mbps",
		Peers:   map[string]string{pubKey: "1mbps"},
	})
	if err != nil {
		t.Fatalf("newLimiterSet: %v", err)
	}

	def := limited.forDst(messages.HashID("other-peer"))
	if def == nil {
		t.Fatal("expected default limiter")
	}
	if math.Abs(float64(def.Limit()-6.25e6)) > 1 {
		t.Fatalf("default limiter rate = %v, want 6.25e6", def.Limit())
	}

	override := limited.forDst(messages.HashID(pubKey))
	if override == nil {
		t.Fatal("expected per-peer limiter")
	}
	if math.Abs(float64(override.Limit()-125000)) > 1 {
		t.Fatalf("per-peer limiter rate = %v, want 125000", override.Limit())
	}

	if _, err := newLimiterSet(RateLimitConfig{Enabled: true, Default: "bogus"}); err == nil {
		t.Fatal("expected error for invalid default rate")
	}
}

func TestLimiterWait(t *testing.T) {
	l, err := newLimiter("1kbps") // 125 bytes/s
	if err != nil {
		t.Fatalf("newLimiter: %v", err)
	}
	if l == nil {
		t.Fatal("expected limiter")
	}

	if err := l.WaitN(context.Background(), 100); err != nil {
		t.Fatalf("first WaitN: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.WaitN(ctx, int(l.Burst())); err == nil {
		t.Fatal("expected WaitN to exceed budget and time out")
	}
}
