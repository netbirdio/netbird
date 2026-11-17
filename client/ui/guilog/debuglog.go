//go:build !android && !ios && !freebsd && !js

// Package guilog manages gui-client.log, which follows the daemon's log level:
// in debug/trace the GUI attaches a rotated file alongside the console so its
// (and the React frontend's forwarded) output is captured for the debug bundle.
package guilog

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

// DebugLog attaches/detaches gui-client.log based on the daemon's log level,
// fed via Apply. The file is left on disk for the debug bundle to collect.
// Disabled (and never touches logging) when the user set --log-file explicitly.
type DebugLog struct {
	uiPath  string
	enabled bool

	mu     sync.Mutex
	fileOn bool
}

// NewDebugLog builds the GUI debug log. enabled is false when the user passed
// --log-file (manual override).
func NewDebugLog(uiPath string, enabled bool) *DebugLog {
	return &DebugLog{uiPath: uiPath, enabled: enabled}
}

// Path returns the GUI log path to register with the daemon, or "" when disabled
// so the daemon won't collect a file the GUI never writes.
func (d *DebugLog) Path() string {
	if !d.enabled {
		return ""
	}
	return d.uiPath
}

// Apply reacts to a daemon log level (the logrus name, e.g. "debug").
// Idempotent via the fileOn guard, so the startup replay plus a racing
// change-event are harmless.
func (d *DebugLog) Apply(level string) {
	if !d.enabled {
		return
	}

	// Compared numerically so there are no hard-coded level-name literals.
	lvl, err := log.ParseLevel(level)
	if err != nil {
		lvl = log.InfoLevel
	}
	debug := lvl >= log.DebugLevel

	d.mu.Lock()
	defer d.mu.Unlock()

	switch {
	case debug && !d.fileOn:
		if err := util.SetLogOutputs(log.StandardLogger(), util.LogConsole, d.uiPath); err != nil {
			log.Errorf("attach GUI file log %s: %v", d.uiPath, err)
			return
		}
		log.SetLevel(lvl)
		d.fileOn = true
		log.Infof("GUI file logging enabled (daemon level %s), writing to %s", level, d.uiPath)
	case !debug && d.fileOn:
		if err := util.SetLogOutputs(log.StandardLogger(), util.LogConsole); err != nil {
			log.Errorf("detach GUI file log: %v", err)
		}
		log.SetLevel(log.InfoLevel)
		d.fileOn = false
		log.Infof("GUI file logging disabled (daemon level: %s)", level)
	}
}
