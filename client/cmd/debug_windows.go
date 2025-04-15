package cmd

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
)

const (
	envListenEvent        = "NB_LISTEN_DEBUG_EVENT"
	debugTriggerEventName = `Global\NetbirdDebugTriggerEvent`

	waitTimeout = 5 * time.Second
)

// SetupDebugHandler sets up a Windows event to listen for a signal to generate a debug bundle.
// Example usage with PowerShell:
// $evt = [System.Threading.EventWaitHandle]::OpenExisting("Global\NetbirdDebugTriggerEvent")
// $evt.Set()
// $evt.Close()
func SetupDebugHandler(
	ctx context.Context,
	config *internal.Config,
	recorder *peer.Status,
	connectClient *internal.ConnectClient,
	logFilePath string,
) {
	env := os.Getenv(envListenEvent)
	if env == "" {
		return
	}

	listenEvent, err := strconv.ParseBool(env)
	if err != nil {
		log.Errorf("Failed to parse %s: %v", envListenEvent, err)
		return
	}
	if !listenEvent {
		return
	}

	eventNamePtr, err := windows.UTF16PtrFromString(debugTriggerEventName)
	if err != nil {
		log.Errorf("Failed to convert event name '%s' to UTF16: %v", debugTriggerEventName, err)
		return
	}

	// TODO: restrict access by ACL
	eventHandle, err := windows.CreateEvent(nil, 1, 0, eventNamePtr)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			log.Warnf("Debug trigger event '%s' already exists. Attempting to open.", debugTriggerEventName)
			// SYNCHRONIZE is needed for WaitForSingleObject, EVENT_MODIFY_STATE for ResetEvent.
			eventHandle, err = windows.OpenEvent(windows.SYNCHRONIZE|windows.EVENT_MODIFY_STATE, false, eventNamePtr)
			if err != nil {
				log.Errorf("Failed to open existing debug trigger event '%s': %v", debugTriggerEventName, err)
				return
			}
			log.Infof("Successfully opened existing debug trigger event '%s'.", debugTriggerEventName)
		} else {
			log.Errorf("Failed to create debug trigger event '%s': %v", debugTriggerEventName, err)
			return
		}
	}

	if eventHandle == windows.InvalidHandle {
		log.Errorf("Obtained an invalid handle for debug trigger event '%s'", debugTriggerEventName)
		return
	}

	log.Infof("Debug handler waiting for signal on event: %s", debugTriggerEventName)

	go waitForEvent(ctx, config, recorder, connectClient, logFilePath, eventHandle)
}

func waitForEvent(
	ctx context.Context,
	config *internal.Config,
	recorder *peer.Status,
	connectClient *internal.ConnectClient,
	logFilePath string,
	eventHandle windows.Handle,
) {
	defer func() {
		if err := windows.CloseHandle(eventHandle); err != nil {
			log.Errorf("Failed to close debug event handle '%s': %v", debugTriggerEventName, err)
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		status, err := windows.WaitForSingleObject(eventHandle, uint32(waitTimeout.Milliseconds()))

		switch status {
		case windows.WAIT_OBJECT_0:
			log.Info("Received signal on debug event. Triggering debug bundle generation.")

			// reset the event so it can be triggered again later (manual reset = 1)
			if err := windows.ResetEvent(eventHandle); err != nil {
				log.Errorf("Failed to reset debug event '%s': %v", debugTriggerEventName, err)
			}

			go generateDebugBundle(config, recorder, connectClient, logFilePath)
		case uint32(windows.WAIT_TIMEOUT):

		default:
			log.Errorf("Unexpected status %d from WaitForSingleObject for debug event '%s': %v", status, debugTriggerEventName, err)
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
}
