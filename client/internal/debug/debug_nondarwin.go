//go:build unix && !darwin && !android

package debug

import (
	log "github.com/sirupsen/logrus"
)

// addDNSInfo collects and adds DNS configuration information to the archive
func (g *BundleGenerator) addDNSInfo() error {
	if err := g.addResolvConf(); err != nil {
		log.Errorf("failed to add resolv.conf: %v", err)
	}

	return nil
}
