package iface

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/iface/bind"
)

const (
	DefaultMTU    = 1280
	DefaultWgPort = 51820
)

// WGIface represents a interface instance
type WGIface struct {
	tun           wgTunDevice
	userspaceBind bool
	mu            sync.Mutex

	configurer wgConfigurer
	filter     PacketFilter
}

type WGStats struct {
	LastHandshake time.Time
	TxBytes       int64
	RxBytes       int64
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
func (w *WGIface) Address() WGAddress {
	return w.tun.WgAddress()
}

// Address6 returns the IPv6 interface address
func (w *WGIface) Address6() *WGAddress {
	return w.tun.WgAddress6()
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

	addr, err := parseWGAddress(newAddr)
	if err != nil {
		return err
	}

	return w.tun.UpdateAddr(addr)
}

// UpdateAddr6 updates the IPv6 address of the interface
func (w *WGIface) UpdateAddr6(newAddr6 string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var addr *WGAddress
	if newAddr6 != "" {
		parsedAddr, err := parseWGAddress(newAddr6)
		if err != nil {
			return err
		}
		addr = &parsedAddr
	}

	return w.tun.UpdateAddr6(addr)
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
// Endpoint is optional
func (w *WGIface) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("updating interface %s peer %s, endpoint %s", w.tun.DeviceName(), peerKey, endpoint)
	return w.configurer.updatePeer(peerKey, allowedIps, keepAlive, endpoint, preSharedKey)
}

// RemovePeer removes a Wireguard Peer from the interface iface
func (w *WGIface) RemovePeer(peerKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("Removing peer %s from interface %s ", peerKey, w.tun.DeviceName())
	return w.configurer.removePeer(peerKey)
}

// AddAllowedIP adds a prefix to the allowed IPs list of peer
func (w *WGIface) AddAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("adding allowed IP to interface %s and peer %s: allowed IP %s ", w.tun.DeviceName(), peerKey, allowedIP)
	return w.configurer.addAllowedIP(peerKey, allowedIP)
}

// RemoveAllowedIP removes a prefix from the allowed IPs list of peer
func (w *WGIface) RemoveAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("removing allowed IP from interface %s and peer %s: allowed IP %s ", w.tun.DeviceName(), peerKey, allowedIP)
	return w.configurer.removeAllowedIP(peerKey, allowedIP)
}

// Close closes the tunnel interface
func (w *WGIface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tun.Close()
}

// SetFilter sets packet filters for the userspace implementation
func (w *WGIface) SetFilter(filter PacketFilter) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.tun.Wrapper() == nil {
		return fmt.Errorf("userspace packet filtering not handled on this device")
	}

	w.filter = filter
	w.filter.SetNetwork(w.tun.WgAddress().Network)

	w.tun.Wrapper().SetFilter(filter)
	return nil
}

// GetFilter returns packet filter used by interface if it uses userspace device implementation
func (w *WGIface) GetFilter() PacketFilter {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.filter
}

// GetDevice to interact with raw device (with filtering)
func (w *WGIface) GetDevice() *DeviceWrapper {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.tun.Wrapper()
}

// GetStats returns the last handshake time, rx and tx bytes for the given peer
func (w *WGIface) GetStats(peerKey string) (WGStats, error) {
	return w.configurer.getStats(peerKey)
}
