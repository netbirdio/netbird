package device

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// tunArgs records the interface parameters Create hands the host.
type tunArgs struct {
	address, addressV6 string
	mtu                int
	dns, searchDomains string
	routes             string
}

// descriptorAdapter is a TunAdapter that offers only a file descriptor.
type descriptorAdapter struct {
	err        error
	configured []tunArgs
}

func (a *descriptorAdapter) ConfigureInterface(address, addressV6 string, mtu int, dns, searchDomains, routes string) (int, error) {
	a.configured = append(a.configured, tunArgs{address, addressV6, mtu, dns, searchDomains, routes})
	return -1, a.err
}

func (a *descriptorAdapter) UpdateAddr(string) error { return nil }

func (a *descriptorAdapter) ProtectSocket(int32) bool { return true }

// providerAdapter also implements TunDeviceProvider, so Create must ask it for the device.
type providerAdapter struct {
	descriptorAdapter
	provided []tunArgs
}

func (a *providerAdapter) TunDevice(address, addressV6 string, mtu int, dns, searchDomains, routes string) (tun.Device, string, error) {
	a.provided = append(a.provided, tunArgs{address, addressV6, mtu, dns, searchDomains, routes})
	return nil, "", a.err
}

// Both adapters fail, so Create returns before it builds a WireGuard device: what is under test is
// which host call it makes and with what, not the device that follows.
func TestWGTunDeviceCreateAsksTheHost(t *testing.T) {
	address, err := wgaddr.ParseWGAddress("100.64.0.1/16")
	require.NoError(t, err)
	address.IPv6 = netip.MustParseAddr("fd00::1")
	address.IPv6Net = netip.MustParsePrefix("fd00::/64")

	// The same parameters on either path: a provider sees exactly what ConfigureInterface would.
	want := tunArgs{
		address:       "100.64.0.1/32",
		addressV6:     "fd00::1/128",
		mtu:           1280,
		dns:           "100.64.0.53",
		searchDomains: "netbird.cloud;example.com",
		routes:        "100.64.0.0/16;10.0.0.0/8",
	}
	create := func(adapter TunAdapter) error {
		dev := NewTunDevice(address, 51820, "", 1280, nil, adapter, false)
		_, err := dev.Create([]string{"100.64.0.0/16", "10.0.0.0/8"}, "100.64.0.53", []string{"netbird.cloud", "example.com"})
		return err
	}

	t.Run("provider is asked for the device, never for a descriptor", func(t *testing.T) {
		adapter := &providerAdapter{descriptorAdapter: descriptorAdapter{err: errors.New("no device")}}

		err := create(adapter)

		assert.ErrorIs(t, err, adapter.err)
		assert.Equal(t, []tunArgs{want}, adapter.provided)
		assert.Empty(t, adapter.configured)
	})

	t.Run("adapter without a provider still configures a descriptor", func(t *testing.T) {
		adapter := &descriptorAdapter{err: errors.New("no descriptor")}

		err := create(adapter)

		assert.ErrorIs(t, err, adapter.err)
		assert.Equal(t, []tunArgs{want}, adapter.configured)
	})
}
