package healthcheck

import (
	"os"
	"testing"
)

//nolint:tenv
func TestGetAttemptThresholdFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected int
	}{
		{"Default attempt threshold when env is not set", "", defaultAttemptThreshold},
		{"Custom attempt threshold when env is set to a valid integer", "3", 3},
		{"Default attempt threshold when env is set to an invalid value", "invalid", defaultAttemptThreshold},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue == "" {
				os.Unsetenv(defaultAttemptThresholdEnv)
			} else {
				os.Setenv(defaultAttemptThresholdEnv, tt.envValue)
			}

			result := getAttemptThresholdFromEnv()
			if result != tt.expected {
				t.Fatalf("Expected %d, got %d", tt.expected, result)
			}

			os.Unsetenv(defaultAttemptThresholdEnv)
		})
	}
}
