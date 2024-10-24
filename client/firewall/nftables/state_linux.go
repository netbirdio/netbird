package nftables

import (
	"fmt"

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
	InterfaceState *InterfaceState `json:"interface_state,omitempty"`
}

func (s *ShutdownState) Name() string {
	return "nftables_state"
}

func (s *ShutdownState) Cleanup() error {
	nft, err := Create(s.InterfaceState)
	if err != nil {
		return fmt.Errorf("create nftables manager: %w", err)
	}

	if err := nft.Reset(nil); err != nil {
		return fmt.Errorf("reset nftables manager: %w", err)
	}

	return nil
}
