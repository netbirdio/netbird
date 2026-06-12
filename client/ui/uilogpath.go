//go:build !android && !ios && !freebsd && !js

package main

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ui/guilog"
)

// uiLogFileName must stay in sync with the daemon's "gui-client*.log.*" glob
// for rotated siblings (addUILog in client/internal/debug).
const uiLogFileName = "gui-client.log"

// uiLogPath returns the GUI log path with native separators, since the daemon
// opens it directly for debug-bundle collection.
func uiLogPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netbird", uiLogFileName), nil
}

// newDebugLog builds the GUI debug log, disabled when userSetLogFile is set
// (manual --log-file override) or the config dir can't be resolved.
func newDebugLog(userSetLogFile bool) *guilog.DebugLog {
	path, err := uiLogPath()
	if err != nil {
		log.Warnf("resolve GUI log path: %v; GUI file logging disabled", err)
		return guilog.NewDebugLog("", false)
	}
	return guilog.NewDebugLog(path, !userSetLogFile)
}
