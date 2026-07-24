package version

import "testing"

func TestIsDevelopmentVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"development", true},
		{"development-0823f3ff9ab1", true},
		{"development-0823f3ff9ab1-dirty", true},
		{"ci-7470fbdd", true},
		{"dev-7470fbdd", true},
		{"0.50.0", false},
		{"v0.31.1-dev", false},
		{"1.0.0-dev", false},
		{"dev", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := IsDevelopmentVersion(tt.version); got != tt.want {
				t.Errorf("IsDevelopmentVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
