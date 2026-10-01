package lazyconn

import "testing"

func TestIsSupported(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"development", true},
		{"0.45.0", true},
		{"v0.45.0", true},
		{"0.45.1", true},
		{"0.45.1-SNAPSHOT-559e6731", true},
		{"v0.45.1-dev", true},
		{"a7d5c522", false},
		{"0.9.6", false},
		{"0.9.6-SNAPSHOT", false},
		{"0.9.6-SNAPSHOT-2033650", false},
		{"meta_wt_version", false},
		{"v0.31.1-dev", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := IsSupported(tt.version); got != tt.want {
				t.Errorf("IsSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}
