package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cobraMutuallyExclusiveAnnotation is the annotation cobra stores on each flag
// of a MarkFlagsMutuallyExclusive group, holding the group as space-separated names.
const cobraMutuallyExclusiveAnnotation = "cobra_annotation_mutually_exclusive"

func TestMutuallyExclusiveFlagGroups(t *testing.T) {
	tests := []struct {
		cmd   *cobra.Command
		flag  string
		group string
	}{
		{cmd: loginCmd, flag: "setup-key", group: "setup-key setup-key-file"},
		{cmd: upCmd, flag: "setup-key", group: "setup-key setup-key-file"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd.Name()+" "+tt.group, func(t *testing.T) {
			f := tt.cmd.Flag(tt.flag)
			require.NotNil(t, f, "%s defines --%s", tt.cmd.Name(), tt.flag)
			assert.Contains(t, f.Annotations[cobraMutuallyExclusiveAnnotation], tt.group, "%s marks [%s] mutually exclusive", tt.cmd.Name(), tt.group)
		})
	}
}

func TestValidateExtendFlags(t *testing.T) {
	tests := []struct {
		name         string
		extend       bool
		setupKey     string
		setupKeyPath string
		wantErr      bool
	}{
		{name: "extend alone", extend: true},
		{name: "setup key alone", setupKey: "key"},
		{name: "extend with setup key", extend: true, setupKey: "key", wantErr: true},
		{name: "extend with setup key file", extend: true, setupKeyPath: "/tmp/key", wantErr: true},
		// --extend=false or NB_EXTEND=false marks the flag as set, but must
		// not block a setup key login.
		{name: "extend false with setup key", setupKey: "key"},
		{name: "extend false with setup key file", setupKeyPath: "/tmp/key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExtendFlags(tt.extend, tt.setupKey, tt.setupKeyPath)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
