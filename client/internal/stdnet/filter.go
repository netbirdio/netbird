package stdnet

import (
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// InterfaceFilter is a function passed to ICE Agent to filter out not allowed interfaces
// to avoid building tunnel over them.
func InterfaceFilter(disallowList []string) func(string) bool {

	return func(iFace string) bool {

		if strings.HasPrefix(iFace, "lo") {
			// hardcoded loopback check to support already installed agents
			return false
		}

		for _, s := range disallowList {
			if strings.HasPrefix(iFace, s) && runtime.GOOS != "ios" {
				log.Tracef("ignoring interface %s - it is not allowed", iFace)
				return false
			}
		}
		// look for unlisted WireGuard interfaces
		wg, err := wgctrl.New()
		if err != nil {
			log.Debugf("trying to create a wgctrl client failed with: %v", err)
			return true
		}
		defer func() {
			_ = wg.Close()
		}()

		_, err = wg.Device(iFace)
		return err != nil
	}
}
