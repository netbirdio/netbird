//go:build !android

package firewall

import (
	"context"
	"fmt"
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
	var errFw error

	switch check() {
	case IPTABLES:
		log.Info("creating an iptables firewall manager")
		fm, errFw = nbiptables.Create(context, iface)
		if errFw != nil {
			log.Errorf("failed to create iptables manager: %s", errFw)
		}
	case NFTABLES:
		log.Info("creating an nftables firewall manager")
		fm, errFw = nbnftables.Create(context, iface)
		if errFw != nil {
			log.Errorf("failed to create nftables manager: %s", errFw)
		}
	default:
		errFw = fmt.Errorf("no firewall manager found")
		log.Info("no firewall manager found, trying to use userspace packet filtering firewall")
	}

	if iface.IsUserspaceBind() {
		var errUsp error
		if errFw == nil {
			fm, errUsp = uspfilter.CreateWithNativeFirewall(iface, fm)
		} else {
			fm, errUsp = uspfilter.Create(iface)
		}
		if errUsp != nil {
			log.Debugf("failed to create userspace filtering firewall: %s", errUsp)
			return nil, errUsp
		}

		if err := fm.AllowNetbird(); err != nil {
			log.Errorf("failed to allow netbird interface traffic: %v", err)
		}
		return fm, nil
	}

	if errFw != nil {
		return nil, errFw
	}

	return fm, nil
}

// check returns the firewall type based on common lib checks. It returns UNKNOWN if no firewall is found.
func check() FWType {
	useIPTABLES := false
	testingChain := "netbird-testing"
	ip, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err == nil && isIptablesClientAvailable(ip) {
		major, minor, _ := ip.GetIptablesVersion()
		// use iptables when its version is lower than 1.8.0 which doesn't work well with our nftables manager
		if major < 1 || (major == 1 && minor < 8) {
			return IPTABLES
		}

		useIPTABLES = true

		// create a testing chain to check if iptables is working and to validate if nftables can be used
		err = ip.NewChain("filter", testingChain)
		if err != nil {
			useIPTABLES = false
		}
	}

	defer func() {
		if !useIPTABLES {
			return
		}
		err = ip.ClearChain("filter", testingChain)
		if err != nil {
			log.Errorf("failed to clear netbird-testing chain: %v", err)
		}
		err = ip.DeleteChain("filter", testingChain)
		if err != nil {
			log.Errorf("failed to delete netbird-testing chain: %v", err)
		}
	}()

	nf := nftables.Conn{}
	if chains, err := nf.ListChains(); err == nil && os.Getenv(SKIP_NFTABLES_ENV) != "true" {
		if !useIPTABLES {
			return NFTABLES
		}
		// search for the testing chain created by iptables client
		// failing to find it means that nftables can be used but the system is using a version of iptables
		// that doesn't work well with our nftables manager
		for _, chain := range chains {
			if chain.Name == testingChain {
				return NFTABLES
			}
		}
	}

	if useIPTABLES {
		return IPTABLES
	}

	return UNKNOWN
}

func isIptablesClientAvailable(client *iptables.IPTables) bool {
	_, err := client.ListChains("filter")
	return err == nil
}
