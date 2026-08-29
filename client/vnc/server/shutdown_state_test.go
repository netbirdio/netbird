//go:build linux && !android

package server

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The start time is what tells a recorded process apart from whatever later
// inherits its PID, so the field offset has to be right and the value stable.
func TestProcessStartTimeIsStable(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no procfs")
	}

	pid := os.Getpid()
	first, err := processStartTime(pid)
	require.NoError(t, err)
	assert.NotZero(t, first, "a running process has a non-zero start time")

	second, err := processStartTime(pid)
	require.NoError(t, err)
	assert.Equal(t, first, second, "start time must not move for a live process")
}

// A comm containing spaces and parentheses must not shift the field offsets,
// which is why parsing starts from the last ')' rather than splitting the line.
func TestProcessStartTimeToleratesOddCommName(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no procfs")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no shell")
	}

	// argv[0] becomes the comm, truncated to 15 chars by the kernel.
	cmd := exec.Command(sh, "-c", "sleep 30")
	cmd.Args[0] = "a (b) c"
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	got, err := processStartTime(cmd.Process.Pid)
	require.NoError(t, err)
	assert.NotZero(t, got)
}

// A PID that never existed must not be reported as ours, and neither must a
// record that carries no start time to compare against.
func TestIsOurProcessRefusesUnidentifiableRecords(t *testing.T) {
	assert.False(t, isOurProcess(sessionProcess{PID: -1}, "xvfb:50"))

	pid := os.Getpid()
	assert.False(t, isOurProcess(sessionProcess{PID: pid}, "xvfb:50"),
		"a record with no recorded start time cannot be matched and must be refused")
}

// describeProcess captures enough to match the process back to itself.
func TestDescribeProcessRoundTrips(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no procfs")
	}

	proc := describeProcess(os.Getpid())
	assert.Equal(t, os.Getpid(), proc.PID)
	assert.NotZero(t, proc.StartTime)

	start, err := processStartTime(proc.PID)
	require.NoError(t, err)
	assert.Equal(t, start, proc.StartTime)
}
