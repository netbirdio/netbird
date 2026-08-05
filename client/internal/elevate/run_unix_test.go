//go:build linux || freebsd

package elevate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePkexec puts a pkexec on PATH that exits with the given code, so the
// mapping from polkit's exit codes onto our errors can be exercised without a
// polkit agent.
func fakePkexec(t *testing.T, exitCode int, stderr string) {
	t.Helper()

	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\necho %s >&2\nexit %d\n", shellQuote(stderr), exitCode)
	if err := os.WriteFile(filepath.Join(dir, "pkexec"), []byte(script), 0o700); err != nil {
		t.Fatalf("write fake pkexec: %v", err)
	}
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakePkexec(t, tt.exitCode, tt.stderr)

			err := run(context.Background(), "/nonexistent/netbird-ui", []string{"--flag"})
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("run() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("run() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// An exit code that is not polkit's is the one-shot's own failure, and has to
// stay distinguishable from a declined prompt: the caller reports it.
func TestRunReportsOneShotFailure(t *testing.T) {
	fakePkexec(t, 3, "the one-shot said no")

	err := run(context.Background(), "/nonexistent/netbird-ui", nil)
	if err == nil {
		t.Fatal("run() = nil, want an error")
	}
	if errors.Is(err, ErrDeclined) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("run() = %v, want a plain failure", err)
	}
}

func TestRunWithoutPkexecIsUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if err := run(context.Background(), "/nonexistent/netbird-ui", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("run() = %v, want ErrUnavailable", err)
	}
	if mechanismAvailable() {
		t.Error("mechanismAvailable() = true without pkexec on PATH")
	}
}
