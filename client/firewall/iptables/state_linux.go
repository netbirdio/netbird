package iptables

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type InterfaceState struct {
	NameStr   string         `json:"name"`
	WGAddress wgaddr.Address `json:"wg_address"`
	MTU       uint16         `json:"mtu"`
}

func (i *InterfaceState) Name() string {
	return i.NameStr
}

func (i *InterfaceState) Address() wgaddr.Address {
	return i.WGAddress
}

type ShutdownState struct {
	sync.Mutex

	InterfaceState *InterfaceState `json:"interface_state,omitempty"`

	RouteRules         routeRules    `json:"route_rules,omitempty"`
	RouteRules6        routeRules    `json:"route_rules_v6,omitempty"`
	RouteIPsetCounter  *ipsetCounter `json:"route_ipset_counter,omitempty"`
	RouteIPsetCounter6 *ipsetCounter `json:"route_ipset_counter_v6,omitempty"`

	ACLEntries  aclEntries `json:"acl_entries,omitempty"`
	ACLEntries6 aclEntries `json:"acl_entries_v6,omitempty"`
}

func (s *ShutdownState) Name() string {
	return "iptables_state"
}

// hasIPv6State reports whether the previous run set up anything for IPv6.
func (s *ShutdownState) hasIPv6State() bool {
	return s.InterfaceState.WGAddress.HasIPv6() || len(s.RouteRules6) > 0 || len(s.ACLEntries6) > 0
}

func (s *ShutdownState) Cleanup() error {
	mtu := s.InterfaceState.MTU
	if mtu == 0 {
		mtu = iface.DefaultMTU
	}
	ipt, err := Create(s.InterfaceState, mtu)
	if err != nil {
		return fmt.Errorf("create iptables manager: %w", err)
	}

	if s.RouteRules != nil {
		ipt.family4.rules = s.RouteRules
	}
	if s.RouteIPsetCounter != nil {
		ipt.family4.ipsetCounter.LoadData(s.RouteIPsetCounter)
	}

	if s.ACLEntries != nil {
		ipt.family4.entries = s.ACLEntries
	}

	// Clean up v6 state even if the current run has no IPv6.
	// The previous run may have left ip6tables rules behind.
	// A failure here must not skip the IPv4 teardown below.
	var merr *multierror.Error
	if !ipt.hasV6Family() {
		if err := ipt.createIPv6Components(s.InterfaceState, mtu, false); err != nil {
			if err := s.v6CreateFailure(err); err != nil {
				merr = multierror.Append(merr, err)
			}
		}
	}
	if ipt.hasV6Family() {
		if s.RouteRules6 != nil {
			ipt.family6.rules = s.RouteRules6
		}
		if s.RouteIPsetCounter6 != nil {
			ipt.family6.ipsetCounter.LoadData(s.RouteIPsetCounter6)
		}
		if s.ACLEntries6 != nil {
			ipt.family6.entries = s.ACLEntries6
		}
	}

	if err := ipt.Close(nil); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("reset iptables manager: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

// v6CreateFailure decides what a failure to set up the IPv6 family for cleanup means. When the
// previous run set up IPv6 it is returned, so the state is kept and the cleanup of what is left
// is retried on the next start. Otherwise there is nothing left to remove and it is only logged.
func (s *ShutdownState) v6CreateFailure(err error) error {
	if s.hasIPv6State() {
		return fmt.Errorf("create v6 components for cleanup: %w", err)
	}
	log.Warnf("failed to create v6 components for cleanup: %v", err)
	return nil
}
