package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/iface/device"
)

// A disabled firewall must still leave the DNS interception hooks in place on a
// userspace bind: the in-process resolver receives queries through them, and the
// system is pointed at that resolver either way.
func TestCreateFirewallDisabledInstallsDNSHooksOnUserspaceBind(t *testing.T) {
	var installed device.PacketFilter
	iface := &MockWGIface{
		IsUserspaceBindFunc: func() bool { return true },
		SetFilterFunc: func(filter device.PacketFilter) error {
			installed = filter
			return nil
		},
	}

	engine := &Engine{
		config:      &EngineConfig{DisableFirewall: true},
		wgInterface: iface,
	}

	require.NoError(t, engine.createFirewall())
	assert.Nil(t, engine.firewall, "no firewall manager should be created")
	assert.IsType(t, &uspfilter.HooksFilter{}, installed)
}

// A kernel bind has no device filter, so nothing should be installed on it.
func TestCreateFirewallDisabledSkipsDNSHooksOnKernelBind(t *testing.T) {
	iface := &MockWGIface{
		IsUserspaceBindFunc: func() bool { return false },
		SetFilterFunc: func(device.PacketFilter) error {
			t.Error("SetFilter called for a kernel bind")
			return nil
		},
	}

	engine := &Engine{
		config:      &EngineConfig{DisableFirewall: true},
		wgInterface: iface,
	}

	require.NoError(t, engine.createFirewall())
	assert.Nil(t, engine.firewall, "no firewall manager should be created")
}
