package iptables

import (
	"fmt"
	"sync"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

type InterfaceState struct {
	NameStr       string          `json:"name"`
	WGAddress     iface.WGAddress `json:"wg_address"`
	UserspaceBind bool            `json:"userspace_bind"`
}

func (i *InterfaceState) Name() string {
	return i.NameStr
}

func (i *InterfaceState) Address() device.WGAddress {
	return i.WGAddress
}

func (i *InterfaceState) IsUserspaceBind() bool {
	return i.UserspaceBind
}

type ShutdownState struct {
	sync.Mutex

	InterfaceState *InterfaceState `json:"interface_state,omitempty"`

	RouteRules        routeRules    `json:"route_rules,omitempty"`
	RouteIPsetCounter *ipsetCounter `json:"route_ipset_counter,omitempty"`

	ACLEntries    aclEntries  `json:"acl_entries,omitempty"`
	ACLIPsetStore *ipsetStore `json:"acl_ipset_store,omitempty"`
}

func (s *ShutdownState) Name() string {
	return "iptables_state"
}

func (s *ShutdownState) Cleanup() error {
	ipt, err := Create(s.InterfaceState)
	if err != nil {
		return fmt.Errorf("create iptables manager: %w", err)
	}

	if s.RouteRules != nil {
		ipt.router.rules = s.RouteRules
	}
	if s.RouteIPsetCounter != nil {
		ipt.router.ipsetCounter.LoadData(s.RouteIPsetCounter)
	}

	if s.ACLEntries != nil {
		ipt.aclMgr.entries = s.ACLEntries
	}
	if s.ACLIPsetStore != nil {
		ipt.aclMgr.ipsetStore = s.ACLIPsetStore
	}

	if err := ipt.Reset(nil); err != nil {
		return fmt.Errorf("reset iptables manager: %w", err)
	}

	return nil
}
