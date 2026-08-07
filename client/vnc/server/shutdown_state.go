//go:build unix

package server

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// ShutdownState tracks VNC virtual session processes for crash recovery.
// Persisted by the state manager; on restart, residual processes are killed.
type ShutdownState struct {
	// Processes maps a description to its PID (e.g., "xvfb:50" -> 1234).
	Processes map[string]int `json:"processes,omitempty"`
}

// Name returns the state name for the state manager.
func (s *ShutdownState) Name() string {
	return "vnc_sessions_state"
}

// Cleanup kills any residual VNC session processes left from a crash.
func (s *ShutdownState) Cleanup() error {
	if len(s.Processes) == 0 {
		return nil
	}

	for desc, pid := range s.Processes {
		if pid <= 0 {
			continue
		}
		if !isOurProcess(pid, desc) {
			log.Debugf("cleanup:skipping PID %d (%s), not ours", pid, desc)
			continue
		}
		log.Infof("cleanup:killing residual process %d (%s)", pid, desc)
		// Kill the process group (negative PID) to get children too.
		if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
			// Try individual process if group kill fails.
			if killErr := syscall.Kill(pid, syscall.SIGKILL); killErr != nil {
				log.Debugf("cleanup: kill pid %d (%s): group kill: %v, single kill: %v", pid, desc, err, killErr)
			}
		}
	}

	s.Processes = nil
	return nil
}

// isOurProcess verifies the PID still belongs to a VNC-related process
// by checking /proc/<pid>/cmdline (Linux) or the process name.
func isOurProcess(pid int, desc string) bool {
	// Check if the process exists at all.
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}

	// On Linux, verify via /proc cmdline.
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		log.Debugf("cleanup: cannot read /proc/%d/cmdline: %v, treating PID as foreign", pid, err)
		return false
	}

	cmd := string(cmdline)
	// Match against expected process types.
	if strings.Contains(desc, "xvfb") || strings.Contains(desc, "xorg") {
		return strings.Contains(cmd, "Xvfb") || strings.Contains(cmd, "Xorg")
	}
	if strings.Contains(desc, "desktop") {
		return strings.Contains(cmd, "session") || strings.Contains(cmd, "plasma") ||
			strings.Contains(cmd, "gnome") || strings.Contains(cmd, "xfce") ||
			strings.Contains(cmd, "dbus-launch")
	}
	return false
}
