package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWarnRosenpassDeprecated(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantWarn bool
	}{
		{name: "no rosenpass flags", args: nil, wantWarn: false},
		{name: "enable rosenpass", args: []string{"--" + enableRosenpassFlag}, wantWarn: true},
		{name: "disable rosenpass", args: []string{"--" + enableRosenpassFlag + "=false"}, wantWarn: false},
		{name: "enable permissive", args: []string{"--" + rosenpassPermissiveFlag}, wantWarn: true},
		{
			name:     "disable both",
			args:     []string{"--" + enableRosenpassFlag + "=false", "--" + rosenpassPermissiveFlag + "=false"},
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The flags bind to the package-level vars, so a fresh command per case
			// resets both the values and the Changed state.
			cmd := &cobra.Command{}
			cmd.Flags().BoolVar(&rosenpassEnabled, enableRosenpassFlag, false, "")
			cmd.Flags().BoolVar(&rosenpassPermissive, rosenpassPermissiveFlag, false, "")
			require.NoError(t, cmd.ParseFlags(tt.args))

			var stderr bytes.Buffer
			cmd.SetErr(&stderr)
			warnRosenpassDeprecated(cmd)

			assert.Equal(t, tt.wantWarn, stderr.Len() > 0, "deprecation warning presence, stderr=%q", stderr.String())
		})
	}
}
