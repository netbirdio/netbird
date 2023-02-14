package iface

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultMTU    = 1280
	DefaultWgPort = 51820
)

// WGIface represents a interface instance
type WGIface struct {
	tun tunDevice
	mu  sync.Mutex
}

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(ifaceName string, address string, mtu int) (*WGIface, error) {
	wgIface := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgIface.tun = newTunDevice(ifaceName, wgAddress, mtu)

	return wgIface, nil
}

// Create creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.tun.create()
}

// Name returns the interface name
func (w *WGIface) Name() string {
	return w.tun.name
}

// Address returns the interface address
func (w *WGIface) Address() WGAddress {
	return w.tun.address
}

// Configure configures a Wireguard interface
// The interface must exist before calling this method (e.g. call interface.Create() before)
func (w *WGIface) Configure(privateKey string, port int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("configuring Wireguard interface %s", w.tun.name)

	log.Debugf("adding Wireguard private key")
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return err
	}
	fwmark := 0
	config := wgtypes.Config{
		PrivateKey:   &key,
		ReplacePeers: true,
		FirewallMark: &fwmark,
		ListenPort:   &port,
	}

	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while configuring interface %s with port %d`, err, w.tun.name, port)
	}
	return nil
}

// UpdateAddr updates address of the interface
func (w *WGIface) UpdateAddr(newAddr string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr, err := parseWGAddress(newAddr)
	if err != nil {
		return err
	}

	return w.tun.updateAddr(addr)
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
// Endpoint is optional
func (w *WGIface) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("updating interface %s peer %s: endpoint %s ", w.tun.name, peerKey, endpoint)

	//parse allowed ips
	_, ipNet, err := net.ParseCIDR(allowedIps)
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:                   peerKeyParsed,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  []net.IPNet{*ipNet},
		PersistentKeepaliveInterval: &keepAlive,
		PresharedKey:                preSharedKey,
		Endpoint:                    endpoint,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while updating peer on interface %s with settings: allowed ips %s, endpoint %s`, err, w.tun.name, allowedIps, endpoint.String())
	}
	return nil
}

// AddAllowedIP adds a prefix to the allowed IPs list of peer
func (w *WGIface) AddAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("adding allowed IP to interface %s and peer %s: allowed IP %s ", w.tun.name, peerKey, allowedIP)

	_, ipNet, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		UpdateOnly:        true,
		ReplaceAllowedIPs: false,
		AllowedIPs:        []net.IPNet{*ipNet},
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while adding allowed Ip to peer on interface %s with settings: allowed ips %s`, err, w.tun.name, allowedIP)
	}
	return nil
}

// RemoveAllowedIP removes a prefix from the allowed IPs list of peer
func (w *WGIface) RemoveAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("removing allowed IP from interface %s and peer %s: allowed IP %s ", w.tun.name, peerKey, allowedIP)

	_, ipNet, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	existingPeer, err := getPeer(w.tun.name, peerKey)
	if err != nil {
		return err
	}

	newAllowedIPs := existingPeer.AllowedIPs

	for i, existingAllowedIP := range existingPeer.AllowedIPs {
		if existingAllowedIP.String() == ipNet.String() {
			newAllowedIPs = append(existingPeer.AllowedIPs[:i], existingPeer.AllowedIPs[i+1:]...)
			break
		}
	}

	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		UpdateOnly:        true,
		ReplaceAllowedIPs: true,
		AllowedIPs:        newAllowedIPs,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while removing allowed IP from peer on interface %s with settings: allowed ips %s`, err, w.tun.name, allowedIP)
	}
	return nil
}

// RemovePeer removes a Wireguard Peer from the interface iface
func (w *WGIface) RemovePeer(peerKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("Removing peer %s from interface %s ", peerKey, w.tun.name)

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	peer := wgtypes.PeerConfig{
		PublicKey: peerKeyParsed,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while removing peer %s from interface %s`, err, peerKey, w.tun.name)
	}
	return nil
}

// Close closes the tunnel interface
func (w *WGIface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tun.close()
}

func getPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return wgtypes.Peer{}, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			log.Errorf("got error while closing wgctl: %v", err)
		}
	}()

	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return wgtypes.Peer{}, err
	}
	for _, peer := range wgDevice.Peers {
		if peer.PublicKey.String() == peerPubKey {
			return peer, nil
		}
	}
	return wgtypes.Peer{}, fmt.Errorf("peer not found")
}

// configureDevice configures the wireguard device
func (w *WGIface) configureDevice(config wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	// validate if device with name exists
	_, err = wg.Device(w.tun.name)
	if err != nil {
		return err
	}
	log.Debugf("got Wireguard device %s", w.tun.name)

	return wg.ConfigureDevice(w.tun.name, config)
}
