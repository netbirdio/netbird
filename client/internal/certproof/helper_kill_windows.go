//go:build windows

package certproof

import (
	"fmt"
	"os/exec"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// startHelper starts cmd inside a job object that is terminated when cmd's context ends
// and closed, killing whatever is left in it, once the helper has been awaited. Killing
// only the helper on Windows leaves its descendants running, and one that holds the
// output pipe would block Wait until it exits, so WaitDelay bounds that wait as well.
func startHelper(cmd *exec.Cmd) (func(), error) {
	job, err := newKillOnCloseJob()
	if err != nil {
		return nil, err
	}
	closeJob := func() {
		if err := windows.CloseHandle(job); err != nil {
			log.Debugf("failed to close certificate proof helper job: %v", err)
		}
	}

	cmd.Cancel = func() error {
		return windows.TerminateJobObject(job, 1)
	}
	cmd.WaitDelay = helperWaitDelay
	if err := cmd.Start(); err != nil {
		closeJob()
		return nil, err
	}

	// A helper outside the job is still killed directly and bounded by WaitDelay; only
	// its descendants would outlive it.
	if err := assignToJob(job, cmd.Process.Pid); err != nil {
		log.Debugf("failed to put certificate proof helper %d in its job: %v", cmd.Process.Pid, err)
		cmd.Cancel = func() error { return cmd.Process.Kill() }
	}
	return closeJob, nil
}

// newKillOnCloseJob creates a job object whose processes are killed when its last handle
// is closed.
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("set job object limits: %w", err)
	}
	return job, nil
}

// assignToJob puts the process pid into job.
func assignToJob(job windows.Handle, pid int) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process: %w", err)
	}
	defer func() {
		_ = windows.CloseHandle(process)
	}()
	return windows.AssignProcessToJobObject(job, process)
}
