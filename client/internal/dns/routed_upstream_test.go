package dns

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutedUpstreamGatingFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		set      bool
		expected routedUpstreamGating
	}{
		{name: "unset", set: false, expected: gatingOff},
		{name: "empty", value: "", set: true, expected: gatingOff},
		{name: "off", value: "off", set: true, expected: gatingOff},
		{name: "startup", value: "startup", set: true, expected: gatingStartup},
		{name: "always", value: "always", set: true, expected: gatingAlways},
		{name: "mixed case", value: "Startup", set: true, expected: gatingStartup},
		{name: "padded", value: "  always  ", set: true, expected: gatingAlways},
		{name: "garbage falls back to off", value: "sometimes", set: true, expected: gatingOff},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv registers the restore, so unsetting afterwards is
			// still cleaned up when the test ends.
			t.Setenv(envRoutedUpstreamGating, tc.value)
			if !tc.set {
				require.NoError(t, os.Unsetenv(envRoutedUpstreamGating))
			}
			assert.Equal(t, tc.expected, routedUpstreamGatingFromEnv())
		})
	}
}

func TestRoutedUpstreamGatingString(t *testing.T) {
	assert.Equal(t, "off", gatingOff.String())
	assert.Equal(t, "startup", gatingStartup.String())
	assert.Equal(t, "always", gatingAlways.String())
}
