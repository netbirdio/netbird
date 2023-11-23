//go:build !android

package firewall

import (
	"context"
	"os"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"

	nbiptables "github.com/netbirdio/netbird/client/firewall/iptables"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnftables "github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

const (
	// UNKNOWN is the default value for the firewall type for unknown firewall type
	UNKNOWN FWType = iota
	// IPTABLES is the value for the iptables firewall type
	IPTABLES
	// NFTABLES is the value for the nftables firewall type
	NFTABLES
)

// SKIP_NFTABLES_ENV is the environment variable to skip nftables check
const SKIP_NFTABLES_ENV = "NB_SKIP_NFTABLES_CHECK"

// FWType is the type for the firewall type
type FWType int

func NewFirewall(context context.Context, iface IFaceMapper) (firewall.Manager, error) {
	// on the linux system we try to user nftables or iptables
	// in any case, because we need to allow netbird interface traffic
	// so we use AllowNetbird traffic from these firewall managers
	// for the userspace packet filtering firewall
	var fm firewall.Manager
	var err error

	switch check() {
	case IPTABLES:
		log.Debug("creating an iptables firewall manager")
		if fm, err = nbiptables.Create(context, iface); err != nil {
			log.Infof("failed to create iptables manager: %s", err)
		}
	case NFTABLES:
		log.Debug("creating an nftables firewall manager")
		if fm, err = nbnftables.Create(context, iface); err != nil {
			log.Debugf("failed to create nftables manager: %s", err)
		}
	default:
		log.Debug("no firewall manager found, try to use userspace packet filtering firewall")
	}

	if iface.IsUserspaceBind() {
		if fm != nil {
			fm, err = uspfilter.CreateWithNativeFirewall(iface, fm)
		} else {
			fm, err = uspfilter.Create(iface)
		}
		if err != nil {
			log.Debugf("failed to create userspace filtering firewall: %s", err)
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	if err := fm.AllowNetbird(); err != nil {
		log.Errorf("failed to allow netbird interface traffic: %v", err)
	}

	return fm, nil
}

// check returns the firewall type based on common lib checks. It returns UNKNOWN if no firewall is found.
func check() FWType {
	nf := nftables.Conn{}
	if _, err := nf.ListChains(); err == nil && os.Getenv(SKIP_NFTABLES_ENV) != "true" {
		return NFTABLES
	}

	ip, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return UNKNOWN
	}
	if isIptablesClientAvailable(ip) {
		return IPTABLES
	}

	return UNKNOWN
}

func isIptablesClientAvailable(client *iptables.IPTables) bool {
	_, err := client.ListChains("filter")
	return err == nil
}
