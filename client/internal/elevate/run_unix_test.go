//go:build linux

package elevate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePkexec puts a pkexec on PATH that exits with the given code, so the
// mapping from polkit's exit codes onto our errors can be exercised without a
// polkit agent.
func fakePkexec(t *testing.T, exitCode int, stderr string) {
	t.Helper()

	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\necho %s >&2\nexit %d\n", shellQuote(stderr), exitCode)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pkexec"), []byte(script), 0o700), "write the fake pkexec")
	t.Setenv("PATH", dir)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func TestRunMapsPkexecExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		stderr   string
		wantErr  error
	}{
		{name: "applied", exitCode: 0},
		{
			name:     "dialog dismissed",
			exitCode: exitDismissed,
			stderr:   "Error executing command as another user: Request dismissed",
			wantErr:  ErrDeclined,
		},
		{
			// What a graphical agent reports for a cancelled prompt. Not a
			// failure: the user was asked and answered.
			name:     "prompt cancelled",
			exitCode: exitNotAuthorized,
			stderr:   "Error executing command as another user: Not authorized",
			wantErr:  ErrDeclined,
		},
		{
			// The same status, but pkexec never got to ask anybody.
			name:     "no agent and no terminal to fall back on",
			exitCode: exitNotAuthorized,
			stderr:   "Error creating textual authentication agent: Error opening current controlling terminal for the process (`/dev/tty'): No such device or address",
			wantErr:  ErrUnavailable,
		},
		{
			// And the same status again once the authorization succeeded and
			// pkexec could not run what it had been authorized to run. Reading
			// that as a refusal would revert the control in silence on a host
			// where elevation is broken.
			name:     "authorized but not runnable",
			exitCode: exitNotAuthorized,
			stderr:   "Error executing command as another user: No such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakePkexec(t, tt.exitCode, tt.stderr)

			err := run(context.Background(), "/nonexistent/netbird-ui", []string{"--flag"})
			switch {
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr, "exit %d said %q", tt.exitCode, tt.stderr)
			case tt.exitCode == 0:
				require.NoError(t, err, "a pkexec that exited cleanly applied the change")
			default:
				require.Error(t, err, "exit %d said %q", tt.exitCode, tt.stderr)
				assert.NotErrorIs(t, err, ErrDeclined, "not the user's answer")
				assert.NotErrorIs(t, err, ErrUnavailable, "not a missing mechanism")
			}
		})
	}
}

// An exit code that is not polkit's is the one-shot's own failure, and has to
// stay distinguishable from a declined prompt: the caller reports it.
func TestRunReportsOneShotFailure(t *testing.T) {
	fakePkexec(t, 3, "the one-shot said no")

	err := run(context.Background(), "/nonexistent/netbird-ui", nil)

	require.Error(t, err, "a one-shot that failed is not a prompt that was answered")
	assert.NotErrorIs(t, err, ErrDeclined, "not the user's answer")
	assert.NotErrorIs(t, err, ErrUnavailable, "not a missing mechanism")
}

func TestRunWithoutPkexecIsUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	err := run(context.Background(), "/nonexistent/netbird-ui", nil)
	require.ErrorIs(t, err, ErrUnavailable, "no pkexec means no mechanism")
	assert.False(t, mechanismAvailable(), "mechanismAvailable without pkexec on PATH")
}
