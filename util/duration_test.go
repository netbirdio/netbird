package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDurationFromEnv(t *testing.T) {
	const key = "NB_TEST_DURATION"
	cases := map[string]time.Duration{
		"":     time.Minute,
		"30s":  30 * time.Second,
		"0":    0,
		"soon": time.Minute,
		"-1s":  time.Minute,
	}
	for value, want := range cases {
		t.Run(value, func(t *testing.T) {
			t.Setenv(key, value)
			assert.Equal(t, want, DurationFromEnv(key, time.Minute), "duration for %q", value)
		})
	}
}
