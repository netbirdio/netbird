package iptables

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// InterfaceAllower opens the NetBird interface on the iptables filter INPUT
// chain so the host firewall doesn't drop traffic the userspace firewall
// handles. It is the fallback used when nftables is unavailable (an
// iptables-legacy host).
//
// It opens INPUT only: the userspace router never forwards in the kernel.
// firewalld trust is handled by the uspfilter manager, not here.
type InterfaceAllower struct {
	ifaceName string
	ipt4      *iptables.IPTables
	// ipt6 is nil when the interface has no IPv6 overlay address.
	ipt6 *iptables.IPTables
}

// NewInterfaceAllower builds an iptables allower for the interface. It returns
// an error when iptables is unavailable, so the caller can fall back to
// firewalld trust.
func NewInterfaceAllower(wgIface iFaceMapper) (*InterfaceAllower, error) {
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("iptables not available: %w", err)
	}
	if _, err := ipt4.ListChains(tableFilter); err != nil {
		return nil, fmt.Errorf("iptables filter table not available: %w", err)
	}

	a := &InterfaceAllower{ifaceName: wgIface.Name(), ipt4: ipt4}

	// Missing v6 must not break the v4 path: open v4 only and continue.
	if wgIface.Address().HasIPv6() {
		ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			log.Warnf("ip6tables not available, opening interface on v4 only: %v", err)
		} else if _, err := ipt6.ListChains(tableFilter); err != nil {
			log.Warnf("ip6tables filter table not available, opening interface on v4 only: %v", err)
		} else {
			a.ipt6 = ipt6
		}
	}

	return a, nil
}

// Apply inserts the interface accept rule on the filter INPUT chain. It removes
// any stale rule first so an unclean exit (e.g. SIGKILL, where Close never ran)
// is recovered deterministically rather than accumulating duplicates.
func (a *InterfaceAllower) Apply() error {
	var merr *multierror.Error
	for _, ipt := range a.clients() {
		if err := ipt.DeleteIfExists(tableFilter, chainInput, a.inputRule()...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("clean stale interface accept rule: %w", err))
		}
		if err := ipt.Insert(tableFilter, chainInput, 1, a.inputRule()...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add interface accept rule: %w", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// Close removes the interface accept rule.
func (a *InterfaceAllower) Close() error {
	var merr *multierror.Error
	for _, ipt := range a.clients() {
		if err := ipt.DeleteIfExists(tableFilter, chainInput, a.inputRule()...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove interface accept rule: %w", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (a *InterfaceAllower) inputRule() []string {
	return []string{"-i", a.ifaceName, "-j", "ACCEPT"}
}

func (a *InterfaceAllower) clients() []*iptables.IPTables {
	clients := []*iptables.IPTables{a.ipt4}
	if a.ipt6 != nil {
		clients = append(clients, a.ipt6)
	}
	return clients
}
