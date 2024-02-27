//go:build !android

package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareOptionsWithTimeout(t *testing.T) {
	tests := []struct {
		name     string
		others   []string
		timeout  int
		expected []string
	}{
		{
			name:     "Append new options with timeout",
			others:   []string{"some config"},
			timeout:  2,
			expected: []string{"some config", "options timeout:2"},
		},
		{
			name:     "Modify existing options to include timeout",
			others:   []string{"some config", "options rotate"},
			timeout:  3,
			expected: []string{"some config", "options timeout:3 rotate"},
		},
		{
			name:     "Existing options with timeout remains unchanged",
			others:   []string{"some config", "options timeout:4"},
			timeout:  5,
			expected: []string{"some config", "options timeout:4"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := prepareOptionsWithTimeout(tc.others, tc.timeout)
			require.Equal(t, len(tc.expected), len(result), "The result should have the same length as expected")
			assert.Equal(t, tc.expected, result, "The result slice should match the expected slice")
		})
	}
}
