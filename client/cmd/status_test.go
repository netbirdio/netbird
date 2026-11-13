package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsingOfIP(t *testing.T) {
	InterfaceIP := "192.168.178.123/16"

	parsedIP := parseInterfaceIP(InterfaceIP)

	assert.Equal(t, "192.168.178.123\n", parsedIP)
}

// resetStatusFlags restores only the status-specific output flags. The root
// flags are shared with other tests in the package, so they must not be
// touched here.
func resetStatusFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range []string{outputFlagName, "detail", "table", "json", "yaml", "ipv4", "ipv6"} {
			f := statusCmd.Flags().Lookup(name)
			require.NotNil(t, f, "flag %s must exist", name)
			require.NoError(t, f.Value.Set(f.DefValue))
			f.Changed = false
		}
	})
}

func TestStatusTableFlagExclusive(t *testing.T) {
	for _, other := range []string{"detail", "json", "yaml", "ipv4", "ipv6"} {
		t.Run(other, func(t *testing.T) {
			resetStatusFlags(t)
			require.NoError(t, statusCmd.Flags().Set("table", "true"))
			require.NoError(t, statusCmd.Flags().Set(other, "true"))

			assert.Error(t, statusCmd.ValidateFlagGroups(), "--table with --%s must be rejected", other)
		})
	}

	t.Run("alone", func(t *testing.T) {
		resetStatusFlags(t)
		require.NoError(t, statusCmd.Flags().Set("table", "true"))

		assert.NoError(t, statusCmd.ValidateFlagGroups())
	})
}

func TestStatusOutputFlagExclusiveWithLegacyFlags(t *testing.T) {
	for _, legacy := range []string{"detail", "table", "json", "yaml", "ipv4", "ipv6"} {
		t.Run(legacy, func(t *testing.T) {
			resetStatusFlags(t)
			require.NoError(t, statusCmd.Flags().Set(outputFlagName, "json"))
			require.NoError(t, statusCmd.Flags().Set(legacy, "true"))

			assert.Error(t, statusCmd.ValidateFlagGroups(), "--output with --%s must be rejected", legacy)
		})
	}
}

func TestLegacyOutputFlagsAreHiddenNotDeprecated(t *testing.T) {
	for _, legacy := range []string{"detail", "table", "json", "yaml", "ipv4", "ipv6"} {
		f := statusCmd.Flags().Lookup(legacy)
		require.NotNil(t, f, "flag %s must exist", legacy)
		assert.True(t, f.Hidden, "--%s must be hidden from help", legacy)
		assert.Empty(t, f.Deprecated, "--%s must not print a deprecation warning", legacy)
	}
}

func TestResolveStatusOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		legacy  *bool
		filter  string
		want    statusOutput
		wantErr bool
	}{
		{name: "default is summary", want: outputSummary},
		{name: "output json", output: "json", want: outputJSON},
		{name: "output is case insensitive", output: "YAML", want: outputYAML},
		{name: "output ipv6", output: "ipv6", want: outputIPv6},
		{name: "unknown output", output: "xml", wantErr: true},
		{name: "legacy table", legacy: &tableFlag, want: outputTable},
		{name: "legacy ipv4", legacy: &ipv4Flag, want: outputIPv4},
		{name: "filter selects detail", filter: "connected", want: outputDetail},
		{name: "filter keeps output", output: "table", filter: "connected", want: outputTable},
		{name: "filter keeps legacy output", legacy: &jsonFlag, filter: "connected", want: outputJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetStatusFlags(t)
			oldFilter := statusFilter
			t.Cleanup(func() { statusFilter = oldFilter })

			outputFlag, statusFilter = tt.output, tt.filter
			if tt.legacy != nil {
				*tt.legacy = true
			}

			got, err := resolveStatusOutput()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "resolved output")
		})
	}
}
