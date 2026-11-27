//go:build unix

package server

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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
	file := filepath.Join(existing, "a-file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	tests := []struct {
		name string
		dir  string
		want string
	}{
		{name: "an existing directory is kept", dir: existing, want: existing},
		{name: "a missing directory falls back to the root", dir: missing, want: "/"},
		{name: "a file in place of the directory falls back to the root", dir: file, want: "/"},
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

	cmd := exec.Command("true")
	cmd.Dir = missing
	_, err := s.startPtyCommandWithSize(cmd, ssh.Pty{Term: "xterm"})
	require.Error(t, err, "a missing working directory must fail a plain PTY start")
	assert.ErrorContains(t, err, "no such file or directory")
}

// The PTY session path must apply the fallback itself, so the session runs the command
// and reports its exit status instead of ending with status 1 before the command starts.
func TestRunPtyCommandInMissingWorkingDir(t *testing.T) {
	s := &Server{}
	session := newPtyTestSession(t)

	cmd := exec.Command("sh", "-c", "exit 7")
	cmd.Dir = filepath.Join(t.TempDir(), "not-created-yet")

	started := s.runPtyCommand(log.NewEntry(log.New()), session, cmd, ssh.Pty{Term: "xterm"}, nil)
	assert.True(t, started, "the PTY command must start despite the missing directory")
	assert.Equal(t, []int{7}, session.exitCodes(), "the session must end with the command's own status")
	assert.Equal(t, "/", cmd.Dir, "the command must run in the root directory")
}

// ptyTestSession is the part of an SSH session that runPtyCommand uses: the context,
// the I/O streams and the exit status. Any other method panics on the nil embedded value.
type ptyTestSession struct {
	ssh.Session
	ctx   ptyTestContext
	mu    sync.Mutex
	exits []int
}

func newPtyTestSession(t *testing.T) *ptyTestSession {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &ptyTestSession{ctx: ptyTestContext{ctx: ctx}}
}

func (p *ptyTestSession) Context() ssh.Context        { return p.ctx }
func (p *ptyTestSession) Read([]byte) (int, error)    { return 0, io.EOF }
func (p *ptyTestSession) Write(b []byte) (int, error) { return len(b), nil }
func (p *ptyTestSession) Stderr() io.ReadWriter       { return p }

func (p *ptyTestSession) Exit(code int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exits = append(p.exits, code)
	return nil
}

func (p *ptyTestSession) exitCodes() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int(nil), p.exits...)
}

type ptyTestContext struct {
	ssh.Context
	ctx context.Context
}

func (c ptyTestContext) Done() <-chan struct{} { return c.ctx.Done() }
func (c ptyTestContext) Err() error            { return c.ctx.Err() }
