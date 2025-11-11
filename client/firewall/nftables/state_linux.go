package nftables

import (
	"fmt"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type InterfaceState struct {
	NameStr       string         `json:"name"`
	WGAddress     wgaddr.Address `json:"wg_address"`
	UserspaceBind bool           `json:"userspace_bind"`
	MTU           uint16         `json:"mtu"`
}

func (i *InterfaceState) Name() string {
	return i.NameStr
}

func (i *InterfaceState) Address() wgaddr.Address {
	return i.WGAddress
}

func (i *InterfaceState) IsUserspaceBind() bool {
	return i.UserspaceBind
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

	if err := nft.Close(nil); err != nil {
		return fmt.Errorf("reset nftables manager: %w", err)
	}

	return nil
}
