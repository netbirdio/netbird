package alignedhb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClampPhase(t *testing.T) {
	const period = 60 * time.Second
	tests := []struct {
		name    string
		phase   time.Duration
		signed  time.Duration
		want    time.Duration
		clamped bool
	}{
		{name: "same phase", phase: 20 * time.Second, signed: 20 * time.Second, want: 20 * time.Second},
		{name: "inside after", phase: 24 * time.Second, signed: 20 * time.Second, want: 24 * time.Second},
		{name: "inside before", phase: 15 * time.Second, signed: 20 * time.Second, want: 15 * time.Second},
		{name: "window edge", phase: 25 * time.Second, signed: 20 * time.Second, want: 25 * time.Second},
		{name: "outside after", phase: 40 * time.Second, signed: 20 * time.Second, want: 25 * time.Second, clamped: true},
		{name: "outside before", phase: 5 * time.Second, signed: 20 * time.Second, want: 15 * time.Second, clamped: true},
		{name: "inside across zero", phase: 58 * time.Second, signed: 2 * time.Second, want: 58 * time.Second},
		{name: "outside across zero before", phase: 50 * time.Second, signed: 2 * time.Second, want: 57 * time.Second, clamped: true},
		{name: "outside across zero after", phase: 10 * time.Second, signed: 58 * time.Second, want: 3 * time.Second, clamped: true},
		{name: "opposite side", phase: 50 * time.Second, signed: 20 * time.Second, want: 25 * time.Second, clamped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, clamped := ClampPhase(tt.phase, tt.signed, period)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.clamped, clamped)
		})
	}
}

// A period shorter than twice the window has no phase outside the window.
func TestClampPhaseShortPeriod(t *testing.T) {
	for _, phase := range []time.Duration{0, 300 * time.Millisecond, 999 * time.Millisecond} {
		got, clamped := ClampPhase(phase, 500*time.Millisecond, time.Second)
		assert.Equal(t, phase, got)
		assert.False(t, clamped)
	}
}
