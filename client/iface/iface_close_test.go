//go:build !android

package iface

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/device"
	nbnetstack "github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// fakeTunDevice implements WGTunDevice and lets the test control when
// Close() returns. It mimics the wireguard-go shutdown path, which blocks
// until its goroutines drain. Some of those goroutines (e.g. the packet
// filter DNS hook in client/internal/dns) call back into WGIface, so if
// WGIface.Close() held w.mu across tun.Close() the shutdown would
// deadlock.
type fakeTunDevice struct {
	closeStarted chan struct{}
	unblockClose chan struct{}
}

func (f *fakeTunDevice) Create() (device.WGConfigurer, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeTunDevice) Up() (*udpmux.UniversalUDPMuxDefault, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeTunDevice) UpdateAddr(wgaddr.Address) error        { return nil }
func (f *fakeTunDevice) WgAddress() wgaddr.Address              { return wgaddr.Address{} }
func (f *fakeTunDevice) MTU() uint16                            { return DefaultMTU }
func (f *fakeTunDevice) DeviceName() string                     { return "nb-close-test" }
func (f *fakeTunDevice) FilteredDevice() *device.FilteredDevice { return nil }
func (f *fakeTunDevice) Device() *wgbackend.Device              { return nil }
func (f *fakeTunDevice) GetNet() *wgbackend.NetstackNet         { return nil }
func (f *fakeTunDevice) GetICEBind() device.EndpointManager     { return nil }

func (f *fakeTunDevice) Close() error {
	close(f.closeStarted)
	<-f.unblockClose
	return nil
}

type fakeProxyFactory struct{}

func (fakeProxyFactory) GetProxy() wgproxy.Proxy { return nil }
func (fakeProxyFactory) Free() error             { return nil }

// TestWGIface_CloseReleasesMutexBeforeTunClose guards against a deadlock
// that surfaces as a macOS test-timeout in
// TestDNSPermanent_updateUpstream: WGIface.Close() used to hold w.mu
// while waiting for the wireguard-go device goroutines to finish, and
// one of those goroutines (the DNS filter hook) calls back into
// WGIface.GetDevice() which needs the same mutex. The fix is to drop
// the lock before tun.Close() returns control.
func TestWGIface_CloseReleasesMutexBeforeTunClose(t *testing.T) {
	// Netstack mode skips the platform interface cleanup in Close, so only
	// the mutex and tun close behavior is exercised.
	t.Setenv(nbnetstack.EnvUseNetstackMode, "true")

	tun := &fakeTunDevice{
		closeStarted: make(chan struct{}),
		unblockClose: make(chan struct{}),
	}
	w := &WGIface{
		tun:            tun,
		wgProxyFactory: fakeProxyFactory{},
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- w.Close()
	}()

	select {
	case <-tun.closeStarted:
	case <-time.After(2 * time.Second):
		close(tun.unblockClose)
		t.Fatal("tun.Close() was never invoked")
	}

	// Simulate the WireGuard read goroutine calling back into WGIface
	// via the packet filter's DNS hook. If Close() still held w.mu
	// during tun.Close(), this would block until the test timeout.
	getDeviceDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = w.GetDevice()
		close(getDeviceDone)
	}()

	select {
	case <-getDeviceDone:
	case <-time.After(2 * time.Second):
		close(tun.unblockClose)
		wg.Wait()
		t.Fatal("GetDevice() deadlocked while WGIface.Close was closing the tun")
	}

	close(tun.unblockClose)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Errorf("WGIface.Close() returned an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WGIface.Close() never returned after the tun was unblocked")
	}
}

// TestWGIface_CloseKeepsOSOwnedInterface covers iOS, where the utun belongs to the
// NEPacketTunnelProvider session and Go closes only its dup of the fd. The interface
// stays up, so waiting for its removal ran into the 5 s timeout on every engine stop
// and then failed on "ifconfig destroy", which the iOS sandbox does not allow.
func TestWGIface_CloseKeepsOSOwnedInterface(t *testing.T) {
	// Without the fix Close tries to destroy the interface after the timeout. The
	// test uses the loopback interface as the one that stays up, so never run it
	// as root.
	if os.Geteuid() == 0 {
		t.Skip("must not run as root")
	}

	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	var name string
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			name = i.Name
			break
		}
	}
	require.NotEmpty(t, name, "test needs a loopback interface that stays up")

	w := &WGIface{
		tun:            &osOwnedTunDevice{name: name},
		tunOwnedByOS:   true,
		wgProxyFactory: fakeProxyFactory{},
	}

	start := time.Now()
	err = w.Close()
	elapsed := time.Since(start)

	assert.NoError(t, err, "Close must not try to remove an interface the OS owns")
	assert.Less(t, elapsed, time.Second, "Close must not wait for an interface the OS owns to go away")
}

// osOwnedTunDevice closes at once and reports the name of an interface that
// stays up after Close.
type osOwnedTunDevice struct {
	fakeTunDevice
	name string
}

func (d *osOwnedTunDevice) DeviceName() string { return d.name }
func (d *osOwnedTunDevice) Close() error       { return nil }
