//go:build !android

package debug

import (
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

func (g *BundleGenerator) addPlatformLog() error {
	if g.logPath != "" && !slices.Contains(util.SpecialLogs, g.logPath) {
		if err := g.addLogfile(); err != nil {
			log.Errorf("failed to add log file to debug bundle: %v", err)
			if err := g.trySystemdLogFallback(); err != nil {
				return err
			}
		}
	} else if err := g.trySystemdLogFallback(); err != nil {
		return err
	}
	return nil
}
