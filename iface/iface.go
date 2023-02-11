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

// NetInterface represents a generic network tunnel interface
type NetInterface interface {
	Close() error
}

// WGIface represents a interface instance
type WGIface struct {
	Port      int
	MTU       int
	name      string
	address   WGAddress
	Interface NetInterface
	mu        sync.Mutex
}

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(iface string, address string, mtu int) (*WGIface, error) {
	wgIface := &WGIface{
		MTU:  mtu,
		name: iface,
		mu:   sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgIface.address = wgAddress

	return wgIface, nil
}

// Name returns the interface name
func (w *WGIface) Name() string {
	return w.name
}

// Address returns the interface address
func (w *WGIface) Address() WGAddress {
	return w.address
}

// Configure configures a Wireguard interface
// The interface must exist before calling this method (e.g. call interface.Create() before)
func (w *WGIface) Configure(privateKey string, port int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("configuring Wireguard interface %s", w.name)

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
		return fmt.Errorf(`received error "%w" while configuring interface %s with port %d`, err, w.name, port)
	}
	return nil
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
// Endpoint is optional
func (w *WGIface) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("updating interface %s peer %s: endpoint %s ", w.name, peerKey, endpoint)

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
		return fmt.Errorf(`received error "%w" while updating peer on interface %s with settings: allowed ips %s, endpoint %s`, err, w.name, allowedIps, endpoint.String())
	}
	return nil
}

// AddAllowedIP adds a prefix to the allowed IPs list of peer
func (w *WGIface) AddAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("adding allowed IP to interface %s and peer %s: allowed IP %s ", w.name, peerKey, allowedIP)

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
		return fmt.Errorf(`received error "%w" while adding allowed Ip to peer on interface %s with settings: allowed ips %s`, err, w.name, allowedIP)
	}
	return nil
}

// RemoveAllowedIP removes a prefix from the allowed IPs list of peer
func (w *WGIface) RemoveAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("removing allowed IP from interface %s and peer %s: allowed IP %s ", w.name, peerKey, allowedIP)

	_, ipNet, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	existingPeer, err := getPeer(w.name, peerKey)
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
		return fmt.Errorf(`received error "%w" while removing allowed IP from peer on interface %s with settings: allowed ips %s`, err, w.name, allowedIP)
	}
	return nil
}

// RemovePeer removes a Wireguard Peer from the interface iface
func (w *WGIface) RemovePeer(peerKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("Removing peer %s from interface %s ", peerKey, w.name)

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
		return fmt.Errorf(`received error "%w" while removing peer %s from interface %s`, err, peerKey, w.name)
	}
	return nil
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
	_, err = wg.Device(w.name)
	if err != nil {
		return err
	}
	log.Debugf("got Wireguard device %s", w.name)

	return wg.ConfigureDevice(w.name, config)
}
