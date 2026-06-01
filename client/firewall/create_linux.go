//go:build !android

package firewall

import (
	"errors"
	"fmt"
	"os"
	"strconv"

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

// SkipNftablesEnv is the environment variable to skip nftables check
const SkipNftablesEnv = "NB_SKIP_NFTABLES_CHECK"

// errNoFirewallManager indicates no kernel firewall backend is present,
// as opposed to a backend that exists but failed to create or initialize.
var errNoFirewallManager = errors.New("no firewall manager found")

// FWType is the type for the firewall type
type FWType int

func NewFirewall(iface IFaceMapper, stateManager *statemanager.Manager, flowLogger nftypes.FlowLogger, disableServerRoutes bool, mtu uint16) (firewall.Manager, error) {
	// We run in userspace mode and force userspace firewall was requested.
	if iface.IsUserspaceBind() && forceUserspaceFirewall() {
		nativeFw, err := createNativeFirewall(iface, stateManager, disableServerRoutes, mtu)
		if err != nil {
			log.Warnf("failed to create native firewall: %v. Proceeding without it", err)
		}

		log.Info("forcing userspace firewall")
		return createUserspaceFirewall(iface, nativeFw, disableServerRoutes, flowLogger, mtu)
	}

	// Use native firewall for either kernel or userspace, the interface appears identical to netfilter
	fm, err := createNativeFirewall(iface, stateManager, disableServerRoutes, mtu)
	switch {
	case err == nil && !iface.IsUserspaceBind():
		// Nothing to do, fall through
	case err == nil && iface.IsUserspaceBind():
		// Native firewall handles packet filtering, but the userspace WireGuard bind
		// needs a device filter for DNS interception hooks. Install a minimal
		// hooks-only filter that passes all traffic through to the kernel firewall.
		if err := iface.SetFilter(&uspfilter.HooksFilter{}); err != nil {
			log.Warnf("failed to set hooks filter, DNS via memory hooks will not work: %v", err)
		}
	case err != nil && !iface.IsUserspaceBind():
		// Kernel cannot fall back to anything else, need to return error
		return nil, err
	case err != nil && iface.IsUserspaceBind():
		// Fall back to the userspace packet filter if native is unavailable
		logNativeFirewallUnavailable(err)
		return createUserspaceFirewall(iface, nil, disableServerRoutes, flowLogger, mtu)
	}

	return fm, nil
}

// createUserspaceFirewall builds the userspace packet filter, optionally
// backed by a native firewall, and allows netbird interface traffic.
func createUserspaceFirewall(iface IFaceMapper, nativeFw firewall.Manager, disableServerRoutes bool, flowLogger nftypes.FlowLogger, mtu uint16) (firewall.Manager, error) {
	fm, err := uspfilter.Create(iface, nativeFw, disableServerRoutes, flowLogger, mtu)
	if err != nil {
		return nil, err
	}

	if err := fm.AllowNetbird(); err != nil {
		log.Errorf("failed to allow netbird interface traffic: %v", err)
	}
	return fm, nil
}

// logNativeFirewallUnavailable logs the fallback to userspace at info level
// when no kernel firewall backend exists, and at warn level otherwise.
func logNativeFirewallUnavailable(err error) {
	if errors.Is(err, errNoFirewallManager) {
		log.Infof("no native firewall backend available: %v. Proceeding with userspace", err)
	} else {
		log.Warnf("failed to create native firewall: %v. Proceeding with userspace", err)
	}
}

func createNativeFirewall(iface IFaceMapper, stateManager *statemanager.Manager, routes bool, mtu uint16) (firewall.Manager, error) {
	fm, err := createFW(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create firewall: %w", err)
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
		return nil, errNoFirewallManager
	}
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

	// Honor the skip env before probing nftables at all.
	if os.Getenv(SkipNftablesEnv) != "true" {
		nf := nftables.Conn{}
		if chains, err := nf.ListChains(); err == nil {
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

func forceUserspaceFirewall() bool {
	val := os.Getenv(EnvForceUserspaceFirewall)
	if val == "" {
		return false
	}

	force, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvForceUserspaceFirewall, err)
		return false
	}
	return force
}
