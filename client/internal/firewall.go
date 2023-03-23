//go:build !linux

package internal

import (
	"fmt"
	"runtime"

	"github.com/netbirdio/netbird/client/firewall"
)

func buildFirewallManager(wgIfaceName string) (fw firewall.Manager, err error) {
	return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
}
