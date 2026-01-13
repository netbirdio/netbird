//go:build !android

package firewall

import (
	"errors"
	"fmt"
	"os"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"

	nbiptables "github.com/netbirdio/netbird/client/firewall/iptables"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnftables "github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
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

func NewFirewall(iface IFaceMapper, stateManager *statemanager.Manager, flowLogger nftypes.FlowLogger, disableServerRoutes bool, mtu uint16) (firewall.Manager, error) {
	// on the linux system we try to user nftables or iptables
	// in any case, because we need to allow netbird interface traffic
	// so we use AllowNetbird traffic from these firewall managers
	// for the userspace packet filtering firewall
	fm, err := createNativeFirewall(iface, stateManager, disableServerRoutes, mtu)

	if !iface.IsUserspaceBind() {
		return fm, err
	}

	if err != nil {
		log.Warnf("failed to create native firewall: %v. Proceeding with userspace", err)
	}
	return createUserspaceFirewall(iface, fm, disableServerRoutes, flowLogger, mtu)
}

func createNativeFirewall(iface IFaceMapper, stateManager *statemanager.Manager, routes bool, mtu uint16) (firewall.Manager, error) {
	fm, err := createFW(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create firewall: %s", err)
	}

	if err = fm.Init(stateManager); err != nil {
		return nil, fmt.Errorf("init firewall: %s", err)
	}

	return fm, nil
}

func createFW(iface IFaceMapper, mtu uint16) (firewall.Manager, error) {
	switch check() {
	case IPTABLES:
		log.Info("creating an iptables firewall manager")
		return nbiptables.Create(iface, mtu)
	case NFTABLES:
		log.Info("creating an nftables firewall manager")
		return nbnftables.Create(iface, mtu)
	default:
		log.Info("no firewall manager found, trying to use userspace packet filtering firewall")
		return nil, errors.New("no firewall manager found")
	}
}

func createUserspaceFirewall(iface IFaceMapper, fm firewall.Manager, disableServerRoutes bool, flowLogger nftypes.FlowLogger, mtu uint16) (firewall.Manager, error) {
	var errUsp error
	if fm != nil {
		fm, errUsp = uspfilter.CreateWithNativeFirewall(iface, fm, disableServerRoutes, flowLogger, mtu)
	} else {
		fm, errUsp = uspfilter.Create(iface, disableServerRoutes, flowLogger, mtu)
	}

	if errUsp != nil {
		return nil, fmt.Errorf("create userspace firewall: %s", errUsp)
	}

	if err := fm.AllowNetbird(); err != nil {
		log.Errorf("failed to allow netbird interface traffic: %v", err)
	}
	return fm, nil
}

// check returns the firewall type based on common lib checks. It returns UNKNOWN if no firewall is found.
func check() FWType {
	useIPTABLES := false
	var iptablesChains []string
	ip, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err == nil && isIptablesClientAvailable(ip) {
		major, minor, _ := ip.GetIptablesVersion()
		// use iptables when its version is lower than 1.8.0 which doesn't work well with our nftables manager
		if major < 1 || (major == 1 && minor < 8) {
			return IPTABLES
		}

		useIPTABLES = true

		iptablesChains, err = ip.ListChains("filter")
		if err != nil {
			log.Errorf("failed to list iptables chains: %s", err)
			useIPTABLES = false
		}
	}

	nf := nftables.Conn{}
	if chains, err := nf.ListChains(); err == nil && os.Getenv(SKIP_NFTABLES_ENV) != "true" {
		if !useIPTABLES {
			return NFTABLES
		}

		// search for chains where table is filter
		// if we find one, we assume that nftables manager can be used with iptables
		for _, chain := range chains {
			if chain.Table.Name == "filter" {
				return NFTABLES
			}
		}

		// check tables for the following constraints:
		// 1. there is no chain in nftables for the filter table and there is at least one chain in iptables, we assume that nftables manager can not be used
		// 2. there is no tables or more than one table, we assume that nftables manager can be used
		// 3. there is only one table and its name is filter, we assume that nftables manager can not be used, since there was no chain in it
		// 4. if we find an error we log and continue with iptables check
		nbTablesList, err := nf.ListTables()
		switch {
		case err == nil && len(iptablesChains) > 0:
			return IPTABLES
		case err == nil && len(nbTablesList) != 1:
			return NFTABLES
		case err == nil && len(nbTablesList) == 1 && nbTablesList[0].Name == "filter":
			return IPTABLES
		case err != nil:
			log.Errorf("failed to list nftables tables on fw manager discovery: %s", err)
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
