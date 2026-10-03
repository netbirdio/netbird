package device

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
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
	dev      tun.Device
	name     string
	provided []tunArgs
}

func (a *providerAdapter) TunDevice(address, addressV6 string, mtu int, dns, searchDomains, routes string) (tun.Device, string, error) {
	a.provided = append(a.provided, tunArgs{address, addressV6, mtu, dns, searchDomains, routes})
	return a.dev, a.name, a.err
}

// hostDevice stands in for the device a host keeps for NetBird. It carries no packets; it only
// blocks reads until it is closed, and records that it was.
type hostDevice struct {
	events chan tun.Event
	done   chan struct{}
	once   sync.Once
}

func newHostDevice() *hostDevice {
	return &hostDevice{events: make(chan tun.Event, 1), done: make(chan struct{})}
}

func (d *hostDevice) File() *os.File { return nil }

func (d *hostDevice) Read([][]byte, []int, int) (int, error) {
	<-d.done
	return 0, os.ErrClosed
}

func (d *hostDevice) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

func (d *hostDevice) MTU() (int, error) { return 1280, nil }

func (d *hostDevice) Name() (string, error) { return "host0", nil }

func (d *hostDevice) Events() <-chan tun.Event { return d.events }

func (d *hostDevice) BatchSize() int { return 1 }

func (d *hostDevice) Close() error {
	d.once.Do(func() {
		close(d.done)
		close(d.events)
	})
	return nil
}

func (d *hostDevice) closed() bool {
	select {
	case <-d.done:
		return true
	default:
		return false
	}
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

// A host that supplies the device also renews it, behind that device. A descriptor handed to a
// running provider-backed device must not become a device of its own and replace the host's.
func TestWGTunDeviceRenewTunRefusesADescriptorFromAProvider(t *testing.T) {
	address, err := wgaddr.ParseWGAddress("100.64.0.1/16")
	require.NoError(t, err)
	dev := NewTunDevice(address, 51820, "", 1280, nil, &providerAdapter{}, false)
	dev.device = &device.Device{}

	fds := make([]int, 2)
	require.NoError(t, unix.Pipe(fds))
	defer func() { _ = unix.Close(fds[1]) }()

	err = dev.RenewTun(fds[0])

	assert.ErrorIs(t, err, errHostSuppliedTun)
	assert.Empty(t, dev.renewableTun.devices, "the descriptor must not become a device")
	_, err = unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0)
	assert.ErrorIs(t, err, unix.EBADF, "the refused descriptor is closed, as on every other RenewTun failure")
}

// NetBird runs on the device and name the provider returns, and owns that device from then on:
// closing the interface closes it, just as it closes a descriptor from ConfigureInterface.
func TestWGTunDeviceRunsOnTheProvidedDevice(t *testing.T) {
	address, err := wgaddr.ParseWGAddress("100.64.0.1/16")
	require.NoError(t, err)
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	host := newHostDevice()
	adapter := &providerAdapter{dev: host, name: "host0"}
	dev := NewTunDevice(address, 0, key.String(), 1280, bind.NewICEBind(nil, address, 1280), adapter, false)

	_, err = dev.Create(nil, "", nil)
	require.NoError(t, err)

	assert.Equal(t, "host0", dev.DeviceName())
	assert.Empty(t, adapter.configured)
	dev.renewableTun.mu.Lock()
	require.Len(t, dev.renewableTun.devices, 1)
	assert.Same(t, host, dev.renewableTun.devices[0].Device)
	dev.renewableTun.mu.Unlock()

	require.NoError(t, dev.Close())
	assert.True(t, host.closed(), "closing the interface closes the device the host supplied")
}
