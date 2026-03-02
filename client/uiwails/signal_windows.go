//go:build windows

package main

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"golang.org/x/sys/windows"
)

const (
	fancyUITriggerEventName = `Global\NetBirdFancyUITriggerEvent`
	waitTimeout             = 5 * time.Second
	desiredAccesses         = windows.SYNCHRONIZE | windows.EVENT_MODIFY_STATE
)

// setupSignalHandler sets up a Windows Event-based signal handler.
// When triggered, it shows the main window.
func setupSignalHandler(ctx context.Context, window *application.WebviewWindow) {
	eventNamePtr, err := windows.UTF16PtrFromString(fancyUITriggerEventName)
	if err != nil {
		log.Errorf("convert event name to UTF16: %v", err)
		return
	}

	eventHandle, err := windows.CreateEvent(nil, 1, 0, eventNamePtr)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			eventHandle, err = windows.OpenEvent(desiredAccesses, false, eventNamePtr)
			if err != nil {
				log.Errorf("open existing trigger event: %v", err)
				return
			}
		} else {
			log.Errorf("create trigger event: %v", err)
			return
		}
	}

	if eventHandle == windows.InvalidHandle {
		log.Errorf("invalid handle for trigger event")
		return
	}

	go waitForWindowsEvent(ctx, eventHandle, window)
}

func waitForWindowsEvent(ctx context.Context, eventHandle windows.Handle, window *application.WebviewWindow) {
	defer func() {
		if err := windows.CloseHandle(eventHandle); err != nil {
			log.Errorf("close event handle: %v", err)
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		status, err := windows.WaitForSingleObject(eventHandle, uint32(waitTimeout.Milliseconds()))

		switch status {
		case windows.WAIT_OBJECT_0:
			log.Info("received trigger event signal, showing window")
			if err := windows.ResetEvent(eventHandle); err != nil {
				log.Errorf("reset event: %v", err)
			}
			window.Show()
		case uint32(windows.WAIT_TIMEOUT):
			// Timeout is expected — loop and poll again.
		default:
			log.Errorf("unexpected WaitForSingleObject status %d: %v", status, err)
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
}
