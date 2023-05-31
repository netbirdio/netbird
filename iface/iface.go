package iface

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/netbirdio/netbird/iface/bind"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultMTU    = 1280
	DefaultWgPort = 51820
)

// WGIface represents a interface instance
type WGIface struct {
	tun           *tunDevice
	configurer    wGConfigurer
	mu            sync.Mutex
	userspaceBind bool
}

// IsUserspaceBind indicates whether this interfaces is userspace with bind.ICEBind
func (w *WGIface) IsUserspaceBind() bool {
	return w.userspaceBind
}

// GetBind returns a userspace implementation of WireGuard Bind interface
func (w *WGIface) GetBind() *bind.ICEBind {
	return w.tun.iceBind
}

// Create creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	log.Debugf("create WireGuard interface %s", w.tun.DeviceName())
	return w.tun.Create()
}

// Name returns the interface name
func (w *WGIface) Name() string {
	return w.tun.DeviceName()
}

// Address returns the interface address
func (w *WGIface) Address() WGAddress {
	return w.tun.WgAddress()
}

// Configure configures a Wireguard interface
// The interface must exist before calling this method (e.g. call interface.Create() before)
func (w *WGIface) Configure(privateKey string, port int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	log.Debugf("configuring Wireguard interface %s", w.tun.DeviceName())
	return w.configurer.configureInterface(privateKey, port)
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

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
// Endpoint is optional
func (w *WGIface) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("updating interface %s peer %s: endpoint %s ", w.tun.DeviceName(), peerKey, endpoint)
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

// SetFiltering sets packet filters for the userspace impelemntation
func (w *WGIface) SetFiltering(filter PacketFilter) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.tun.wrapper == nil {
		return fmt.Errorf("userspace packet filtering not handled on this device")
	}

	filter.SetNetwork(w.tun.address.Network)
	w.tun.wrapper.SetFiltering(filter)
	return nil
}
