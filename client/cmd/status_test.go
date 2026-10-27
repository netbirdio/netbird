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

// resetStatusFlags restores only the status-specific output flags. The global
// root flags (setup-key and friends) are shared with other tests in the
// package, so they must not be touched here.
func resetStatusFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range []string{"detail", "table", "json", "yaml", "ipv4", "ipv6"} {
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

func TestFilterEnablesDetailOnlyWithoutOutputFormat(t *testing.T) {
	tests := []struct {
		name       string
		table      bool
		json       bool
		wantDetail bool
	}{
		{name: "no format", wantDetail: true},
		{name: "table", table: true, wantDetail: false},
		{name: "json", json: true, wantDetail: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetStatusFlags(t)
			tableFlag, jsonFlag = tt.table, tt.json

			enableDetailFlagWhenFilterFlag()

			assert.Equal(t, tt.wantDetail, detailFlag)
		})
	}
}
