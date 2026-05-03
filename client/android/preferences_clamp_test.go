package android

import (
	"math"
	"testing"
)

// Codex review: Preferences.SetXxxSeconds used to cast int64 directly
// to uint32, silently wrapping negatives into huge positives and
// truncating values >MaxUint32. Lock down the new clamp behavior.
func TestClampUint32Seconds(t *testing.T) {
	maxU := uint32(math.MaxUint32)
	tests := []struct {
		name  string
		input int64
		want  uint32
	}{
		{"zero", 0, 0},
		{"one", 1, 1},
		{"3h_typical", 10800, 10800},
		{"24h_typical", 86400, 86400},
		{"max_uint32_exact", int64(math.MaxUint32), maxU},
		{"max_uint32_plus_one_clamps", int64(math.MaxUint32) + 1, maxU},
		{"int64_max_clamps", math.MaxInt64, maxU},
		{"negative_one_clamps_to_zero", -1, 0},
		{"negative_huge_clamps_to_zero", -86400, 0},
		{"int64_min_clamps_to_zero", math.MinInt64, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clampUint32Seconds(tc.input)
			if got != tc.want {
				t.Errorf("clampUint32Seconds(%d) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
