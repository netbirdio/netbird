//go:build unix

package server

import (
	"io"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFallbackMissingWorkingDir(t *testing.T) {
	logger := log.NewEntry(log.New())
	existing := t.TempDir()
	missing := filepath.Join(existing, "not-created-yet")

	tests := []struct {
		name string
		dir  string
		want string
	}{
		{name: "an existing directory is kept", dir: existing, want: existing},
		{name: "a missing directory falls back to the root", dir: missing, want: "/"},
		{name: "no directory is left to the command", dir: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("true")
			cmd.Dir = tt.dir
			fallbackMissingWorkingDir(logger, cmd)
			assert.Equal(t, tt.want, cmd.Dir)
		})
	}
}

// A user whose home directory PAM creates at the first login has none when the session
// starts. Starting the command there fails inside the child, which Go reports as a failed
// fork/exec of the program, and login never runs its PAM session.
func TestPtyStartInMissingWorkingDir(t *testing.T) {
	s := &Server{}
	missing := filepath.Join(t.TempDir(), "not-created-yet")
	ptyReq := ssh.Pty{Term: "xterm"}

	cmd := exec.Command("true")
	cmd.Dir = missing
	_, err := s.startPtyCommandWithSize(cmd, ptyReq)
	require.Error(t, err, "a missing working directory must fail the PTY start")
	assert.ErrorContains(t, err, "no such file or directory")

	cmd = exec.Command("true")
	cmd.Dir = missing
	fallbackMissingWorkingDir(log.NewEntry(log.New()), cmd)
	ptmx, err := s.startPtyCommandWithSize(cmd, ptyReq)
	require.NoError(t, err, "the PTY must start once the directory falls back to the root")
	_, _ = io.Copy(io.Discard, ptmx)
	require.NoError(t, cmd.Wait())
	require.NoError(t, ptmx.Close())
}
