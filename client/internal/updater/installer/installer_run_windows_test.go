package installer

import (
	"errors"
	"os/exec"
	"slices"
	"strconv"
	"testing"
)

// exitErrorWithCode returns a real *exec.ExitError carrying the given exit code.
func exitErrorWithCode(t *testing.T, code int) error {
	t.Helper()

	err := exec.Command("cmd.exe", "/c", "exit "+strconv.Itoa(code)).Run()
	if err == nil {
		t.Fatalf("expected a non-zero exit for code %d", code)
	}
	return err
}

func TestIsRebootPending(t *testing.T) {
	tests := []struct {
		name string
		code int
		want bool
	}{
		{name: "reboot required", code: msiRebootRequired, want: true},
		{name: "reboot initiated", code: msiRebootInitiated, want: true},
		{name: "generic failure", code: 1603, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRebootPending(exitErrorWithCode(t, tt.code)); got != tt.want {
				t.Errorf("isRebootPending(exit %d) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// TestProcessIDsByNameAndTerminate spawns a long-running system process, finds it
// by name and terminates it, covering the path the updater uses to release the UI
// image file before the installer replaces it.
func TestProcessIDsByNameAndTerminate(t *testing.T) {
	cmd := exec.Command("ping.exe", "-n", "60", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ping: %v", err)
	}

	pid := uint32(cmd.Process.Pid)
	killed := false
	t.Cleanup(func() {
		if !killed {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	// Name matching must be case-insensitive: the snapshot reports PING.EXE.
	pids, err := processIDsByName("ping.exe")
	if err != nil {
		t.Fatalf("processIDsByName: %v", err)
	}

	if !slices.Contains(pids, pid) {
		t.Fatalf("PID %d not among the ping.exe processes found: %v", pid, pids)
	}

	if err := terminateProcess(pid); err != nil {
		t.Fatalf("terminateProcess: %v", err)
	}
	killed = true

	// terminateProcess only returns once the handle has signalled, so the process
	// is already gone and Wait must not block. It exits with the code passed to
	// TerminateProcess, which is 0, so Wait reports no error.
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait for terminated ping: %v", err)
	}
	if !cmd.ProcessState.Exited() {
		t.Error("process did not exit after terminateProcess")
	}

	remaining, err := processIDsByName("ping.exe")
	if err != nil {
		t.Fatalf("processIDsByName after terminate: %v", err)
	}
	if slices.Contains(remaining, pid) {
		t.Errorf("PID %d still listed after terminateProcess", pid)
	}
}

func TestProcessIDsByNameNoMatch(t *testing.T) {
	pids, err := processIDsByName("netbird-nonexistent-process.exe")
	if err != nil {
		t.Fatalf("processIDsByName: %v", err)
	}
	if len(pids) != 0 {
		t.Errorf("expected no matches, got %v", pids)
	}
}

func TestIsRebootPendingNonExitError(t *testing.T) {
	if isRebootPending(errors.New("start installer: file not found")) {
		t.Error("a non-exit error must not be treated as a pending reboot")
	}
}
