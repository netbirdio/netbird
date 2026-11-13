package nftables

import (
	"fmt"

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
	InterfaceState *InterfaceState `json:"interface_state,omitempty"`
}

func (s *ShutdownState) Name() string {
	return "nftables_state"
}

func (s *ShutdownState) Cleanup() error {
	mtu := s.InterfaceState.MTU
	if mtu == 0 {
		mtu = iface.DefaultMTU
	}
	nft, err := Create(s.InterfaceState, mtu)
	if err != nil {
		return fmt.Errorf("create nftables manager: %w", err)
	}

	// Clean up v6 state even if the current run would not have any: the previous run may have
	// put its accept rules into IPv6 chains of the host.
	if !nft.hasV6Family() {
		nft.createIPv6Components(getTableName(), s.InterfaceState, mtu)
	}

	if err := nft.Close(nil); err != nil {
		return fmt.Errorf("reset nftables manager: %w", err)
	}

	return nil
}
