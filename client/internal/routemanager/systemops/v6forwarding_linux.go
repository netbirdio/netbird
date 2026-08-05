//go:build !android

package systemops

import (
	"fmt"
	"net"
	"os"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/sysctl"
)

const (
	// 1 (default) accepts RAs only while forwarding is off; 2 keeps RA
	// acceptance on regardless, so RA-installed host defaults survive our
	// v6 forwarding flip.
	acceptRAInterfacePath  = "net.ipv6.conf.%s.accept_ra"
	acceptRAProcPathFormat = "/proc/sys/net/ipv6/conf/%s/accept_ra"
)

// EnableV6IPForwarding bumps accept_ra=2 on host v6 interfaces before flipping
// forwarding=1, so RA-installed host defaults survive. Returns the prior values
// of sysctls we actually changed; entries already at the target are omitted.
func EnableV6IPForwarding(wgIfaceName string) (map[string]int, error) {
	saved := map[string]int{}
	bumpAcceptRA(saved, wgIfaceName)

	oldVal, err := sysctl.Set(ipv6ForwardingPath, 1, false)
	if err != nil {
		return saved, err
	}
	if oldVal != 1 {
		saved[ipv6ForwardingPath] = oldVal
	}
	return saved, nil
}

// DisableV6IPForwarding restores what EnableV6IPForwarding captured.
func DisableV6IPForwarding(saved map[string]int) error {
	var result *multierror.Error
	for key, value := range saved {
		if _, err := sysctl.Set(key, value, false); err != nil {
			result = multierror.Append(result, fmt.Errorf("restore %s: %w", key, err))
		}
	}
	return nberrors.FormatErrorOrNil(result)
}

func bumpAcceptRA(saved map[string]int, wgIfaceName string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Warnf("list interfaces for accept_ra: %v", err)
		return
	}
	for _, intf := range interfaces {
		if intf.Name == "lo" || intf.Name == wgIfaceName {
			continue
		}
		bumpAcceptRAForInterface(saved, intf.Name)
	}
}

func bumpAcceptRAForInterface(saved map[string]int, name string) {
	key := fmt.Sprintf(acceptRAInterfacePath, name)
	// Build procfs path from name, not the dotted key: VLAN names like eth0.100.
	if _, err := os.Stat(fmt.Sprintf(acceptRAProcPathFormat, name)); err != nil {
		return
	}
	// onlyIfOne=true: leave admin overrides (0, 2) alone.
	oldVal, err := sysctl.Set(key, 2, true)
	if err != nil {
		log.Warnf("bump %s: %v", key, err)
		return
	}
	if oldVal != 2 {
		saved[key] = oldVal
	}
}
