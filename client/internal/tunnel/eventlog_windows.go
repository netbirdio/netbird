//go:build windows

// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"fmt"

	"golang.org/x/sys/windows/svc/eventlog"
)

// Event IDs for Windows Event Log
const (
	EventIDServiceStart      = 1000
	EventIDServiceStop       = 1001
	EventIDTunnelConnected   = 1100
	EventIDTunnelDisconnected = 1101
	EventIDAuthSuccess       = 1200
	EventIDAuthFailure       = 1201
	EventIDACLHardened       = 1300
	EventIDSetupKeyRemoved   = 1301
	EventIDConfigError       = 1400
)

// EventSourceName is the name of the event source in Windows Event Log.
const EventSourceName = "NetBirdMachine"

var eventLog *eventlog.Log

// RegisterEventSource registers the event source in Windows Event Log.
// This requires Administrator privileges and only needs to be done once during installation.
func RegisterEventSource() error {
	err := eventlog.InstallAsEventCreate(EventSourceName, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil {
		return fmt.Errorf("install event source: %w", err)
	}
	return nil
}

// InitEventLog initializes the event log for writing.
func InitEventLog() error {
	var err error
	eventLog, err = eventlog.Open(EventSourceName)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	return nil
}

// CloseEventLog closes the event log.
func CloseEventLog() {
	if eventLog != nil {
		eventLog.Close()
		eventLog = nil
	}
}

// LogInfo logs an informational event.
func LogInfo(eventID uint32, message string) error {
	if eventLog == nil {
		return fmt.Errorf("event log not initialized")
	}
	return eventLog.Info(eventID, message)
}

// LogWarning logs a warning event.
func LogWarning(eventID uint32, message string) error {
	if eventLog == nil {
		return fmt.Errorf("event log not initialized")
	}
	return eventLog.Warning(eventID, message)
}

// LogError logs an error event.
func LogError(eventID uint32, message string) error {
	if eventLog == nil {
		return fmt.Errorf("event log not initialized")
	}
	return eventLog.Error(eventID, message)
}

// LogACLHardened logs when ACLs are hardened on a path.
func LogACLHardened(path string) error {
	return LogInfo(EventIDACLHardened, fmt.Sprintf("ACLs hardened on: %s", path))
}

// LogSetupKeyRemoved logs when the setup key is removed after bootstrap.
func LogSetupKeyRemoved() error {
	return LogInfo(EventIDSetupKeyRemoved, "Setup key removed after successful bootstrap")
}

// LogTunnelConnected logs when the tunnel connects.
func LogTunnelConnected(serverAddr string) error {
	return LogInfo(EventIDTunnelConnected, fmt.Sprintf("Tunnel connected to: %s", serverAddr))
}

// LogTunnelDisconnected logs when the tunnel disconnects.
func LogTunnelDisconnected(reason string) error {
	return LogInfo(EventIDTunnelDisconnected, fmt.Sprintf("Tunnel disconnected: %s", reason))
}
