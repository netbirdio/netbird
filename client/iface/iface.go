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
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/monotime"
)

const (
	DefaultMTU         = 1280
	MinMTU             = 576
	MaxMTU             = 8192
	DefaultWgPort      = 51820
	WgInterfaceDefault = configurer.WgInterfaceDefault
)

var (
	// ErrIfaceNotFound is returned when the WireGuard interface is not found
	ErrIfaceNotFound = fmt.Errorf("wireguard interface not found")
)

// ValidateMTU validates that MTU is within acceptable range
func ValidateMTU(mtu uint16) error {
	if mtu < MinMTU {
		return fmt.Errorf("MTU %d below minimum (%d bytes)", mtu, MinMTU)
	}
	if mtu > MaxMTU {
		return fmt.Errorf("MTU %d exceeds maximum supported size (%d bytes)", mtu, MaxMTU)
	}
	return nil
}

type wgProxyFactory interface {
	GetProxy() wgproxy.Proxy
	GetProxyPort() uint16
	Free() error
}

type WGIFaceOpts struct {
	IFaceName    string
	Address      string
	WGPort       int
	WGPrivKey    string
	MTU          uint16
	MobileArgs   *device.MobileIFaceArguments
	TransportNet transport.Net
	FilterFn     udpmux.FilterFn
	DisableDNS   bool
}

// WGIface represents an interface instance
type WGIface struct {
	tun           WGTunDevice
	userspaceBind bool
	mu            sync.Mutex

	configurer     device.WGConfigurer
	filter         device.PacketFilter
	wgProxyFactory wgProxyFactory
}

func (w *WGIface) GetProxy() wgproxy.Proxy {
	return w.wgProxyFactory.GetProxy()
}

// GetProxyPort returns the proxy port used by the WireGuard proxy.
// Returns 0 if no proxy port is used (e.g., for userspace WireGuard).
func (w *WGIface) GetProxyPort() uint16 {
	return w.wgProxyFactory.GetProxyPort()
}

// GetBind returns the EndpointManager userspace bind mode.
func (w *WGIface) GetBind() device.EndpointManager {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.tun == nil {
		return nil
	}
	return w.tun.GetICEBind()
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

func (w *WGIface) MTU() uint16 {
	return w.tun.MTU()
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
func (w *WGIface) Up() (*udpmux.UniversalUDPMuxDefault, error) {
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
	return w.configurer.UpdatePeer(peerKey, allowedIps, keepAlive, endpoint, preSharedKey)
}

func (w *WGIface) RemoveEndpointAddress(peerKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.configurer == nil {
		return ErrIfaceNotFound
	}

	log.Debugf("Removing endpoint address: %s", peerKey)
	return w.configurer.RemoveEndpointAddress(peerKey)
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
	return w.configurer.RemoveAllowedIP(peerKey, allowedIP)
}

// Close closes the tunnel interface
func (w *WGIface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var result *multierror.Error

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

// SetPresharedKey sets or updates the preshared key for a peer.
// If updateOnly is true, only updates existing peer; if false, creates or updates.
func (w *WGIface) SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.configurer == nil {
		return ErrIfaceNotFound
	}

	return w.configurer.SetPresharedKey(peerKey, psk, updateOnly)
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
