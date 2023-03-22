package internal

import (
	"fmt"
	"runtime"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
)

func buildFirewallManager() (fw firewall.Manager, err error) {
	switch runtime.GOOS {
	case "linux":
		return iptables.Create()

	default:
		return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
	}
}
