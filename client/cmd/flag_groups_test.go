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
		{cmd: loginCmd, flag: "extend", group: "extend setup-key"},
		{cmd: loginCmd, flag: "extend", group: "extend setup-key-file"},
		{cmd: loginCmd, flag: "setup-key", group: "setup-key setup-key-file"},
		{cmd: upCmd, flag: "setup-key", group: "setup-key setup-key-file"},
		{cmd: sshCmd, flag: "user", group: "user login"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd.Name()+" "+tt.group, func(t *testing.T) {
			f := tt.cmd.Flag(tt.flag)
			require.NotNil(t, f, "%s defines --%s", tt.cmd.Name(), tt.flag)
			assert.Contains(t, f.Annotations[cobraMutuallyExclusiveAnnotation], tt.group, "%s marks [%s] mutually exclusive", tt.cmd.Name(), tt.group)
		})
	}
}
