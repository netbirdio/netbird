package iface

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	wgdevice "golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/monotime"
)

const (
	DefaultMTU         = 1280
	DefaultWgPort      = 51820
	WgInterfaceDefault = configurer.WgInterfaceDefault
)

var (
	// ErrIfaceNotFound is returned when the WireGuard interface is not found
	ErrIfaceNotFound = fmt.Errorf("wireguard interface not found")
)

type wgProxyFactory interface {
	GetProxy() wgproxy.Proxy
	Free() error
}

type WGIFaceOpts struct {
	IFaceName    string
	Address      string
	WGPort       int
	WGPrivKey    string
	MTU          int
	MobileArgs   *device.MobileIFaceArguments
	TransportNet transport.Net
	FilterFn     bind.FilterFn
	DisableDNS   bool
}

// WGIface represents an interface instance
type WGIface struct {
	tun           WGTunDevice
	userspaceBind bool
	mu            sync.Mutex

	configurer     device.WGConfigurer
	batcher        *WGBatcher
	filter         device.PacketFilter
	wgProxyFactory wgProxyFactory
}

func (w *WGIface) GetProxy() wgproxy.Proxy {
	return w.wgProxyFactory.GetProxy()
}

// IsUserspaceBind indicates whether this interfaces is userspace with bind.ICEBind
func (w *WGIface) IsUserspaceBind() bool {
	return w.userspaceBind
}

// Name returns the interface name
func (w *WGIface) Name() string {
	return w.tun.DeviceName()
}

// Address returns the interface address
func (w *WGIface) Address() wgaddr.Address {
	return w.tun.WgAddress()
}

// ToInterface returns the net.Interface for the Wireguard interface
func (r *WGIface) ToInterface() *net.Interface {
	name := r.tun.DeviceName()
	intf, err := net.InterfaceByName(name)
	if err != nil {
		log.Warnf("Failed to get interface by name %s: %v", name, err)
		intf = &net.Interface{
			Name: name,
		}
	}
	return intf
}

// Up configures a Wireguard interface
// The interface must exist before calling this method (e.g. call interface.Create() before)
func (w *WGIface) Up() (*bind.UniversalUDPMuxDefault, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.tun.Up()
}

// UpdateAddr updates address of the interface
func (w *WGIface) UpdateAddr(newAddr string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr, err := wgaddr.ParseWGAddress(newAddr)
	if err != nil {
		return err
	}

	return w.tun.UpdateAddr(addr)
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
// Endpoint is optional.
// If allowedIps is given it will be added to the existing ones.
func (w *WGIface) UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.configurer == nil {
		return ErrIfaceNotFound
	}

	log.Debugf("updating interface %s peer %s, endpoint %s, allowedIPs %v", w.tun.DeviceName(), peerKey, endpoint, allowedIps)

	if endpoint != nil && w.batcher != nil {
		if err := w.batcher.Flush(); err != nil {
			log.Warnf("failed to flush batched operations: %v", err)
		}
	}
	return w.configurer.UpdatePeer(peerKey, allowedIps, keepAlive, endpoint, preSharedKey)
}

// RemovePeer removes a Wireguard Peer from the interface iface
func (w *WGIface) RemovePeer(peerKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.configurer == nil {
		return ErrIfaceNotFound
	}

	log.Debugf("Removing peer %s from interface %s ", peerKey, w.tun.DeviceName())
	return w.configurer.RemovePeer(peerKey)
}

// AddAllowedIP adds a prefix to the allowed IPs list of peer
func (w *WGIface) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.configurer == nil {
		return ErrIfaceNotFound
	}

	log.Debugf("Adding allowed IP to interface %s and peer %s: allowed IP %s ", w.tun.DeviceName(), peerKey, allowedIP)

	if w.batcher != nil {
		return w.batcher.AddAllowedIP(peerKey, allowedIP)
	}
	return w.configurer.AddAllowedIP(peerKey, allowedIP)
}

// RemoveAllowedIP removes a prefix from the allowed IPs list of peer
func (w *WGIface) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.configurer == nil {
		return ErrIfaceNotFound
	}

	log.Debugf("Removing allowed IP from interface %s and peer %s: allowed IP %s ", w.tun.DeviceName(), peerKey, allowedIP)

	if w.batcher != nil {
		return w.batcher.RemoveAllowedIP(peerKey, allowedIP)
	}
	return w.configurer.RemoveAllowedIP(peerKey, allowedIP)
}

// Close closes the tunnel interface
func (w *WGIface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var result *multierror.Error

	if w.batcher != nil {
		if err := w.batcher.Close(); err != nil {
			result = multierror.Append(result, fmt.Errorf("failed to close WireGuard batcher: %w", err))
		}
	}

	if err := w.wgProxyFactory.Free(); err != nil {
		result = multierror.Append(result, fmt.Errorf("failed to free WireGuard proxy: %w", err))
	}

	if err := w.tun.Close(); err != nil {
		result = multierror.Append(result, fmt.Errorf("failed to close wireguard interface %s: %w", w.Name(), err))
	}

	if err := w.waitUntilRemoved(); err != nil {
		log.Warnf("failed to remove WireGuard interface %s: %v", w.Name(), err)
		if err := w.Destroy(); err != nil {
			result = multierror.Append(result, fmt.Errorf("failed to remove WireGuard interface %s: %w", w.Name(), err))
			return errors.FormatErrorOrNil(result)
		}
		log.Infof("interface %s successfully removed", w.Name())
	}

	return errors.FormatErrorOrNil(result)
}

// SetFilter sets packet filters for the userspace implementation
func (w *WGIface) SetFilter(filter device.PacketFilter) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.tun.FilteredDevice() == nil {
		return fmt.Errorf("userspace packet filtering not handled on this device")
	}

	w.filter = filter

	w.tun.FilteredDevice().SetFilter(filter)
	return nil
}

// GetFilter returns packet filter used by interface if it uses userspace device implementation
func (w *WGIface) GetFilter() device.PacketFilter {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.filter
}

// GetDevice to interact with raw device (with filtering)
func (w *WGIface) GetDevice() *device.FilteredDevice {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.tun.FilteredDevice()
}

// GetWGDevice returns the WireGuard device
func (w *WGIface) GetWGDevice() *wgdevice.Device {
	return w.tun.Device()
}

// GetStats returns the last handshake time, rx and tx bytes
func (w *WGIface) GetStats() (map[string]configurer.WGStats, error) {
	if w.configurer == nil {
		return nil, ErrIfaceNotFound
	}
	return w.configurer.GetStats()
}

func (w *WGIface) LastActivities() map[string]monotime.Time {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.configurer == nil {
		return nil
	}

	return w.configurer.LastActivities()

}

func (w *WGIface) FullStats() (*configurer.Stats, error) {
	if w.configurer == nil {
		return nil, ErrIfaceNotFound
	}

	return w.configurer.FullStats()
}

func (w *WGIface) waitUntilRemoved() error {
	maxWaitTime := 5 * time.Second
	timeout := time.NewTimer(maxWaitTime)
	defer timeout.Stop()

	for {
		iface, err := net.InterfaceByName(w.Name())
		if err != nil {
			if _, ok := err.(*net.OpError); ok {
				log.Infof("interface %s has been removed", w.Name())
				return nil
			}
			log.Debugf("failed to get interface by name %s: %v", w.Name(), err)
		} else if iface == nil {
			log.Infof("interface %s has been removed", w.Name())
			return nil
		}

		select {
		case <-timeout.C:
			return fmt.Errorf("timeout when waiting for interface %s to be removed", w.Name())
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// GetNet returns the netstack.Net for the netstack device
func (w *WGIface) GetNet() *netstack.Net {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.tun.GetNet()
}
