//go:build ios

package debug

import (
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// swiftLogFile is the Swift app log written by the iOS app into the same log
// directory as the Go client log, so it can be collected into the bundle.
const swiftLogFile = "swift-log.log"

// addPlatformLog collects logs for the iOS debug bundle. iOS has no logcat or
// systemd journal, so we rely on file-based logs. addLogfile handles the Go
// client log (logPath) with rotation, the stderr/stdout companions and
// anonymization. The iOS app writes its own Swift log into the same directory,
// so we add it alongside the Go log.
func (g *BundleGenerator) addPlatformLog() error {
	if err := g.addLogfile(); err != nil {
		return err
	}

	if g.logPath == "" {
		return nil
	}

	swiftLogPath := filepath.Join(filepath.Dir(g.logPath), swiftLogFile)
	if err := g.addSingleLogfile(swiftLogPath, swiftLogFile); err != nil {
		// The Swift log is best-effort: the app may not have written it yet.
		log.Warnf("failed to add %s to debug bundle: %v", swiftLogFile, err)
	}

	return nil
}
