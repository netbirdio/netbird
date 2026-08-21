//go:build !android && !ios && !freebsd && !js

package main

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/configs"
	"github.com/netbirdio/netbird/client/ui/guilog"
)

// uiLogPath returns the GUI log path with native separators, since the daemon
// opens it directly for debug-bundle collection. The file name comes from
// configs.UILogFile so the daemon validates and collects the same name.
func uiLogPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netbird", configs.UILogFile), nil
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
