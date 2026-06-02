package tokencmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "empty string returns zero",
			input:    "",
			expected: 0,
		},
		{
			name:     "days suffix",
			input:    "30d",
			expected: 30 * 24 * time.Hour,
		},
		{
			name:     "one day",
			input:    "1d",
			expected: 24 * time.Hour,
		},
		{
			name:     "365 days",
			input:    "365d",
			expected: 365 * 24 * time.Hour,
		},
		{
			name:     "hours via Go duration",
			input:    "24h",
			expected: 24 * time.Hour,
		},
		{
			name:     "minutes via Go duration",
			input:    "30m",
			expected: 30 * time.Minute,
		},
		{
			name:     "complex Go duration",
			input:    "1h30m",
			expected: 90 * time.Minute,
		},
		{
			name:    "invalid day format",
			input:   "abcd",
			wantErr: true,
		},
		{
			name:    "negative days",
			input:   "-1d",
			wantErr: true,
		},
		{
			name:    "zero days",
			input:   "0d",
			wantErr: true,
		},
		{
			name:    "non-numeric days",
			input:   "xyzd",
			wantErr: true,
		},
		{
			name:    "negative Go duration",
			input:   "-24h",
			wantErr: true,
		},
		{
			name:    "zero Go duration",
			input:   "0s",
			wantErr: true,
		},
		{
			name:    "invalid Go duration",
			input:   "notaduration",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDuration(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
