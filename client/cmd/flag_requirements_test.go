package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRequiresCommand builds a command where --url and --insecure require --upload.
func testRequiresCommand(t *testing.T) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{Use: "bundle"}
	cmd.Flags().Bool("upload", false, "")
	cmd.Flags().String("url", "https://default.example", "")
	cmd.Flags().Bool("insecure", false, "")
	markFlagRequires(cmd, "url", "upload")
	markFlagRequires(cmd, "insecure", "upload")
	return cmd
}

func TestValidateFlagRequirements(t *testing.T) {
	tests := []struct {
		name    string
		cli     map[string]string
		env     map[string]string
		wantErr string
	}{
		{
			name: "no flags",
		},
		{
			name: "required flag alone",
			cli:  map[string]string{"upload": "true"},
		},
		{
			name: "dependent flag with required flag",
			cli:  map[string]string{"upload": "true", "url": "https://self-hosted.example"},
		},
		{
			name:    "dependent flag without required flag",
			cli:     map[string]string{"url": "https://self-hosted.example"},
			wantErr: "--url requires --upload",
		},
		{
			name:    "dependent flag with required flag set to false",
			cli:     map[string]string{"upload": "false", "insecure": "true"},
			wantErr: "--insecure requires --upload",
		},
		{
			// The environment can satisfy a requirement.
			name: "required flag from the environment",
			cli:  map[string]string{"url": "https://self-hosted.example"},
			env:  map[string]string{"upload": "true"},
		},
		{
			// A variable exported in the shell must not break commands
			// that ignore it.
			name: "dependent flag from the environment only",
			env:  map[string]string{"url": "https://self-hosted.example"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := testRequiresCommand(t)
			for name, value := range tt.cli {
				require.NoError(t, cmd.Flags().Set(name, value))
			}

			// Mirrors the root PersistentPreRunE: capture the command line,
			// then apply the environment.
			setOnCommandLine := commandLineFlags(cmd)
			for name, value := range tt.env {
				require.NoError(t, cmd.Flags().Set(name, value))
			}

			err := validateFlagRequirements(cmd, setOnCommandLine)

			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.wantErr, err.Error(), "error names both flags")
		})
	}
}

func TestMarkFlagRequiresUnknownFlagPanics(t *testing.T) {
	cmd := &cobra.Command{Use: "bundle"}
	cmd.Flags().Bool("upload", false, "")

	assert.Panics(t, func() { markFlagRequires(cmd, "missing", "upload") }, "an unknown flag is a programming error")
}

func TestDebugUploadFlagsRequireUploadBundle(t *testing.T) {
	for _, cmd := range []*cobra.Command{debugBundleCmd, forCmd} {
		for _, name := range []string{"upload-bundle-url", "upload-bundle-insecure"} {
			f := cmd.Flags().Lookup(name)
			require.NotNil(t, f, "%s defines --%s", cmd.Name(), name)
			assert.Equal(t, []string{"upload-bundle"}, f.Annotations[requiresFlagAnnotation], "%s --%s requires --upload-bundle", cmd.Name(), name)
		}
	}
}
