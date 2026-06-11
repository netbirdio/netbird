//go:build !android && !ios && !freebsd && !js

// Package guilog manages the desktop UI's own file log (gui-client.log), which
// follows the daemon's log level: when the daemon is in debug/trace the GUI
// attaches a rotated file alongside the console so its (and the React frontend's
// forwarded) output is captured for the debug bundle. It is intentionally not a
// Wails service — it has no frontend-facing methods and generates no TS
// bindings — so it lives outside client/ui/services.
package guilog

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

// DebugLog is the daemon-debug-driven GUI file log. The daemon publishes a
// marked "log-level-changed" SystemEvent over SubscribeEvents (both on change
// and once per new subscription, so a daemon already in debug is picked up at
// startup); services.DaemonFeed routes it here via Apply.
//
// When the daemon is in debug/trace and the GUI owns its log (no manual
// --log-file), it attaches a rotated gui-client.log alongside the console and
// raises the logrus level; back to a higher level it detaches the file and
// restores info. The file is left on disk (rotated by timberjack) for the debug
// bundle to collect. When the user set --log-file explicitly, it is disabled and
// never touches logging.
type DebugLog struct {
	uiPath  string
	enabled bool

	mu     sync.Mutex
	fileOn bool
}

// NewDebugLog builds the GUI debug log. uiPath is the absolute gui-client.log
// path; enabled is false when the user passed --log-file (manual override), in
// which case it leaves logging untouched.
func NewDebugLog(uiPath string, enabled bool) *DebugLog {
	return &DebugLog{uiPath: uiPath, enabled: enabled}
}

// Path returns the GUI log path to register with the daemon, or "" when the GUI
// doesn't own its log (manual --log-file) — in that case the daemon shouldn't
// try to collect a gui-client.log the GUI never writes.
func (d *DebugLog) Path() string {
	if !d.enabled {
		return ""
	}
	return d.uiPath
}

// Apply reacts to a daemon log level (the lowercase logrus name, e.g. "debug").
// Idempotent: repeated identical levels are no-ops, so the startup replay plus a
// racing change-event do no harm.
func (d *DebugLog) Apply(level string) {
	if !d.enabled {
		return
	}

	// "debug or more verbose" (debug/trace) turns the file log on; anything less
	// verbose turns it off. Compare numerically against logrus' own levels so
	// there are no hard-coded level-name literals.
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
