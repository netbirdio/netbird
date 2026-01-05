//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	quickActionsTriggerEventName = `Global\NetBirdQuickActionsTriggerEvent`
	waitTimeout                  = 5 * time.Second
	// SYNCHRONIZE is needed for WaitForSingleObject, EVENT_MODIFY_STATE for ResetEvent.
	desiredAccesses = windows.SYNCHRONIZE | windows.EVENT_MODIFY_STATE
)

func getEventNameUint16Pointer() (*uint16, error) {
	eventNamePtr, err := windows.UTF16PtrFromString(quickActionsTriggerEventName)
	if err != nil {
		log.Errorf("Failed to convert event name '%s' to UTF16: %v", quickActionsTriggerEventName, err)
		return nil, err
	}

	return eventNamePtr, nil
}

// setupSignalHandler sets up signal handling for Windows.
// Windows doesn't support SIGUSR1, so this uses a similar approach using windows.Events.
func (s *serviceClient) setupSignalHandler(ctx context.Context) {
	eventNamePtr, err := getEventNameUint16Pointer()
	if err != nil {
		return
	}

	eventHandle, err := windows.CreateEvent(nil, 1, 0, eventNamePtr)

	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			log.Warnf("Quick actions trigger event '%s' already exists. Attempting to open.", quickActionsTriggerEventName)
			eventHandle, err = windows.OpenEvent(desiredAccesses, false, eventNamePtr)
			if err != nil {
				log.Errorf("Failed to open existing quick actions trigger event '%s': %v", quickActionsTriggerEventName, err)
				return
			}
			log.Infof("Successfully opened existing quick actions trigger event '%s'.", quickActionsTriggerEventName)
		} else {
			log.Errorf("Failed to create quick actions trigger event '%s': %v", quickActionsTriggerEventName, err)
			return
		}
	}

	if eventHandle == windows.InvalidHandle {
		log.Errorf("Obtained an invalid handle for quick actions trigger event '%s'", quickActionsTriggerEventName)
		return
	}

	log.Infof("Quick actions handler waiting for signal on event: %s", quickActionsTriggerEventName)

	go s.waitForEvent(ctx, eventHandle)
}

func (s *serviceClient) waitForEvent(ctx context.Context, eventHandle windows.Handle) {
	defer func() {
		if err := windows.CloseHandle(eventHandle); err != nil {
			log.Errorf("Failed to close quick actions event handle '%s': %v", quickActionsTriggerEventName, err)
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		status, err := windows.WaitForSingleObject(eventHandle, uint32(waitTimeout.Milliseconds()))

		switch status {
		case windows.WAIT_OBJECT_0:
			log.Info("Received signal on quick actions event. Opening quick actions window.")

			// reset the event so it can be triggered again later (manual reset == 1)
			if err := windows.ResetEvent(eventHandle); err != nil {
				log.Errorf("Failed to reset quick actions event '%s': %v", quickActionsTriggerEventName, err)
			}

			s.openQuickActions()
		case uint32(windows.WAIT_TIMEOUT):

		default:
			if isDone := logUnexpectedStatus(ctx, status, err); isDone {
				return
			}
		}
	}
}

func logUnexpectedStatus(ctx context.Context, status uint32, err error) bool {
	log.Errorf("Unexpected status %d from WaitForSingleObject for quick actions event '%s': %v",
		status, quickActionsTriggerEventName, err)
	select {
	case <-time.After(5 * time.Second):
		return false
	case <-ctx.Done():
		return true
	}
}

// openQuickActions opens the quick actions window by spawning a new process.
func (s *serviceClient) openQuickActions() {
	proc, err := os.Executable()
	if err != nil {
		log.Errorf("get executable path: %v", err)
		return
	}

	cmd := exec.CommandContext(s.ctx, proc,
		"--quick-actions=true",
		"--daemon-addr="+s.addr,
	)

	if out := s.attachOutput(cmd); out != nil {
		defer func() {
			if err := out.Close(); err != nil {
				log.Errorf("close log file %s: %v", s.logFile, err)
			}
		}()
	}

	log.Infof("running command: %s --quick-actions=true --daemon-addr=%s", proc, s.addr)

	if err := cmd.Start(); err != nil {
		log.Errorf("error starting quick actions window: %v", err)
		return
	}

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Debugf("quick actions window exited: %v", err)
		}
	}()
}

func sendShowWindowSignal(pid int32) error {
	_, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}

	eventNamePtr, err := getEventNameUint16Pointer()
	if err != nil {
		return err
	}

	eventHandle, err := windows.OpenEvent(desiredAccesses, false, eventNamePtr)
	if err != nil {
		return err
	}

	err = windows.SetEvent(eventHandle)
	if err != nil {
		return fmt.Errorf("error setting event: %w", err)
	}

	return nil
}
