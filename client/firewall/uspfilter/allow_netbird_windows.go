package uspfilter

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	luid, err := m.getWgInterfaceLUID()
	if err != nil {
		return err
	}

	return firewall.EnableFirewall(uint64(luid), true, nil)
}

// getWgInterfaceLUID retrieves the tunnel interface locally unique identifier (LUID)
// from globally unique identifier (GUID) of the Manager's wireguard interface.
func (m *Manager) getWgInterfaceLUID() (winipcfg.LUID, error) {
	guidString, err := m.wgIface.GetInterfaceGUIDString()
	if err != nil {
		return 0, err
	}

	guid, err := windows.GUIDFromString(guidString)
	if err != nil {
		return 0, fmt.Errorf("invalid GUID %q: %v", guidString, err)
	}

	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		return luid, fmt.Errorf("no interface with GUID %q: %v", guid, err)
	}

	return luid, nil
}
