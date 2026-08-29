//go:build unix

package server

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// sessionProcess identifies one virtual-session process well enough to be
// signalled safely after a crash.
//
// A PID on its own is not enough: by the time the daemon restarts, the kernel
// may have handed that number to something else, and Cleanup signals the whole
// process group. Start time is what makes the identity stable — it is fixed for
// the life of a process and a reused PID always has a later one — and the UID
// keeps us from signalling another user's processes even if both matched.
type sessionProcess struct {
	PID int `json:"pid"`
	// StartTime is field 22 of /proc/<pid>/stat, in clock ticks since boot.
	StartTime uint64 `json:"startTime,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
}

// ShutdownState tracks VNC virtual session processes for crash recovery.
// Persisted by the state manager; on restart, residual processes are killed.
type ShutdownState struct {
	// Processes maps a description to the process it names (e.g. "xvfb:50").
	Processes map[string]sessionProcess `json:"processes,omitempty"`
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

	for desc, proc := range s.Processes {
		if proc.PID <= 0 {
			continue
		}
		if !isOurProcess(proc, desc) {
			log.Debugf("cleanup: skipping PID %d (%s), not ours", proc.PID, desc)
			continue
		}
		log.Infof("cleanup: killing residual process %d (%s)", proc.PID, desc)
		// Kill the process group (negative PID) to get children too.
		if err := syscall.Kill(-proc.PID, syscall.SIGTERM); err != nil {
			// Try individual process if group kill fails.
			if killErr := syscall.Kill(proc.PID, syscall.SIGKILL); killErr != nil {
				log.Debugf("cleanup: kill pid %d (%s): group kill: %v, single kill: %v", proc.PID, desc, err, killErr)
			}
		}
	}

	s.Processes = nil
	return nil
}

// describeProcess captures the identity of a freshly started process so a later
// Cleanup can tell it apart from whatever inherits its PID.
func describeProcess(pid int) sessionProcess {
	proc := sessionProcess{PID: pid}
	if start, err := processStartTime(pid); err == nil {
		proc.StartTime = start
	} else {
		log.Debugf("read start time for pid %d: %v", pid, err)
	}
	if uid, err := processUID(pid); err == nil {
		proc.UID = uid
	} else {
		log.Debugf("read uid for pid %d: %v", pid, err)
	}
	return proc
}

// isOurProcess verifies the PID still belongs to the VNC-related process it was
// recorded for, by matching desc against /proc/<pid>/cmdline and confirming the
// process start time and owner are the ones recorded. Anything that cannot be
// read, or does not match, is reported as foreign so cleanup never signals a
// process it has not identified.
func isOurProcess(proc sessionProcess, desc string) bool {
	// Check if the process exists at all.
	if err := syscall.Kill(proc.PID, 0); err != nil {
		return false
	}

	// A recorded start time that no longer matches means the PID was reused.
	// A record without one predates the check and cannot be trusted to be the
	// same process, so it is refused as well.
	if proc.StartTime == 0 {
		log.Debugf("cleanup: pid %d (%s) has no recorded start time", proc.PID, desc)
		return false
	}
	start, err := processStartTime(proc.PID)
	if err != nil {
		log.Debugf("cleanup: cannot read start time for pid %d: %v, treating PID as foreign", proc.PID, err)
		return false
	}
	if start != proc.StartTime {
		log.Debugf("cleanup: pid %d (%s) started at %d, recorded %d: PID was reused", proc.PID, desc, start, proc.StartTime)
		return false
	}

	if uid, err := processUID(proc.PID); err != nil || uid != proc.UID {
		log.Debugf("cleanup: pid %d (%s) owner mismatch (err=%v): treating PID as foreign", proc.PID, desc, err)
		return false
	}

	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", proc.PID))
	if err != nil {
		log.Debugf("cleanup: cannot read /proc/%d/cmdline: %v, treating PID as foreign", proc.PID, err)
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

// processStartTime reads field 22 of /proc/<pid>/stat, the process start time in
// clock ticks since boot. Parsed from the last ')' so a comm containing spaces
// or parentheses cannot shift the field offsets.
func processStartTime(pid int) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	commEnd := bytes.LastIndexByte(raw, ')')
	if commEnd < 0 {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	// Fields after comm: state is field 3, so start time (field 22) is the
	// 20th entry of the remainder.
	fields := strings.Fields(string(raw[commEnd+1:]))
	const startTimeOffset = 19
	if len(fields) <= startTimeOffset {
		return 0, fmt.Errorf("/proc/%d/stat has %d fields after comm", pid, len(fields))
	}
	return strconv.ParseUint(fields[startTimeOffset], 10, 64)
}

// processUID reads the real UID that owns a process.
func processUID(pid int) (uint32, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d", pid), &st); err != nil {
		return 0, err
	}
	return st.Uid, nil
}
