//go:build !android && !ios && !freebsd && !js

package main

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ui/guilog"
)

// uiLogFileName is the base name of the GUI's log. Rotated siblings
// (gui-client.log.*, *.gz) share the prefix; the daemon's debug bundle globs
// "gui-client*.log.*" to collect them (see addUILog in client/internal/debug).
const uiLogFileName = "gui-client.log"

// uiLogPath resolves os.UserConfigDir()/netbird/gui-client.log — the per-OS-user
// path the GUI writes its log to while the daemon is in debug, and the path it
// registers with the daemon for debug-bundle collection. Native separators are
// preserved (the daemon os.Open()s this path).
func uiLogPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netbird", uiLogFileName), nil
}

// newDebugLog builds the GUI debug log. userSetLogFile disables it (manual
// --log-file override). If the config dir can't be resolved it's created
// disabled, so the GUI keeps working without file logging.
func newDebugLog(userSetLogFile bool) *guilog.DebugLog {
	path, err := uiLogPath()
	if err != nil {
		log.Warnf("resolve GUI log path: %v; GUI file logging disabled", err)
		return guilog.NewDebugLog("", false)
	}
	return guilog.NewDebugLog(path, !userSetLogFile)
}
