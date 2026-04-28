//go:build windows

package main

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	quickActionsTriggerEventName = `Global\NetBirdQuickActionsTriggerEvent`
	waitTimeout                  = 5 * time.Second
	desiredAccesses              = windows.SYNCHRONIZE | windows.EVENT_MODIFY_STATE

	// WaitForSingleObject returns this when the timeout elapses without the
	// object being signalled. golang.org/x/sys/windows does not expose it.
	waitTimeoutCode uint32 = 0x00000102
)

// listenForShowSignal opens the main window when an external process pulses
// the named event Global\NetBirdQuickActionsTriggerEvent. Mirrors the trigger
// the legacy Fyne UI used so the installer and CLI integrations keep working.
func listenForShowSignal(ctx context.Context, tray *Tray) {
	namePtr, err := windows.UTF16PtrFromString(quickActionsTriggerEventName)
	if err != nil {
		log.Errorf("trigger event name: %v", err)
		return
	}

	handle, err := windows.CreateEvent(nil, 1, 0, namePtr)
	if err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			log.Errorf("create trigger event %q: %v", quickActionsTriggerEventName, err)
			return
		}
		handle, err = windows.OpenEvent(desiredAccesses, false, namePtr)
		if err != nil {
			log.Errorf("open trigger event %q: %v", quickActionsTriggerEventName, err)
			return
		}
	}

	if handle == windows.InvalidHandle {
		log.Errorf("invalid handle for trigger event %q", quickActionsTriggerEventName)
		return
	}

	go waitForTrigger(ctx, handle, tray)
}

func waitForTrigger(ctx context.Context, handle windows.Handle, tray *Tray) {
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			log.Errorf("close trigger event handle: %v", err)
		}
	}()

	timeoutMs := uint32(waitTimeout / time.Millisecond)
	for {
		if ctx.Err() != nil {
			return
		}
		ev, err := windows.WaitForSingleObject(handle, timeoutMs)
		switch {
		case err != nil:
			log.Errorf("wait trigger event: %v", err)
			return
		case ev == waitTimeoutCode:
			continue
		case ev == windows.WAIT_OBJECT_0:
			if err := windows.ResetEvent(handle); err != nil {
				log.Errorf("reset trigger event: %v", err)
			}
			tray.ShowWindow()
		}
	}
}
