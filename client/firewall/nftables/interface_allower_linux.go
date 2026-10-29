package nftables

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// InterfaceAllower opens the NetBird interface in the kernel's filter table and
// external chains and keeps them reconciled via a netlink monitor, so the host
// firewall doesn't drop traffic the NetBird firewall handles. It is used by the
// userspace firewall, where routing happens in the forwarder, so only INPUT is
// opened (the userspace router never forwards in the kernel).
//
// It owns its own families/connection and never creates a netbird work table.
// firewalld trust is handled by the caller, not here. Its operations are serial
// (Apply before the monitor starts; reconciles run on the single monitor
// goroutine; Close stops the monitor before removing), so it needs no locking.
//
// TODO: this opens nftables and the iptables-nft filter table (detected via
// nft), but not a legacy-iptables ruleset running in parallel with nftables.
// Such a host would keep its legacy filter chains closed for the interface.
type InterfaceAllower struct {
	family4    *family
	family6    *family
	extMonitor *externalChainMonitor
}

// NewInterfaceAllower builds an allower for the given interface. It returns an
// error when nftables is unavailable (e.g. an iptables-legacy host), so the
// caller can fall back to firewalld trust.
func NewInterfaceAllower(wgIface iFaceMapper, mtu uint16) (*InterfaceAllower, error) {
	tableName := getTableName()

	family4 := newFamily(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv4}, wgIface, mtu)

	// Probe nftables availability before committing to this backend.
	if _, err := family4.conn.ListChainsOfTableFamily(nftables.TableFamilyINet); err != nil {
		return nil, fmt.Errorf("nftables not available: %w", err)
	}

	a := &InterfaceAllower{family4: family4}

	if wgIface.Address().HasIPv6() {
		a.family6 = newFamily(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv6}, wgIface, mtu)
	}

	a.extMonitor = newExternalChainMonitor(a)
	return a, nil
}

// Apply opens the interface (INPUT only) in the foreign filter chains and starts
// reconciling them on nftables changes.
func (a *InterfaceAllower) Apply() error {
	var merr *multierror.Error
	for _, f := range a.families() {
		// Remove any stale accepts first so a prior unclean exit (e.g. SIGKILL,
		// where Close never ran) is recovered deterministically rather than
		// accumulating duplicate rules on the iptables filter table.
		if err := f.removeAcceptFilterRules(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("clean stale accept rules: %w", err))
		}
		if err := f.openInterface(false); err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	a.extMonitor.start()
	return nberrors.FormatErrorOrNil(merr)
}

// families returns the configured address families (v4, and v6 when present).
func (a *InterfaceAllower) families() []*family {
	families := []*family{a.family4}
	if a.family6 != nil {
		families = append(families, a.family6)
	}
	return families
}

// reconcileExternalChains re-applies the INPUT accepts to external chains. It
// implements externalChainReconciler for the monitor.
func (a *InterfaceAllower) reconcileExternalChains() error {
	var merr *multierror.Error
	for _, f := range a.families() {
		if err := f.acceptExternalChainsRules(false); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// Close stops the monitor and removes the accept rules.
func (a *InterfaceAllower) Close() error {
	a.extMonitor.stop()

	var merr *multierror.Error
	for _, f := range a.families() {
		if err := f.removeAcceptFilterRules(); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}
