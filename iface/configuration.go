package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"time"
)

// GetName returns the interface name
func (w *WGIface) GetName() string {
	return w.Name
}

// GetAddress returns the interface address
func (w *WGIface) GetAddress() WGAddress {
	return w.Address
}

// configureDevice configures the wireguard device
func (w *WGIface) configureDevice(config wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	// validate if device with name exists
	_, err = wg.Device(w.Name)
	if err != nil {
		return err
	}
	log.Debugf("got Wireguard device %s", w.Name)

	return wg.ConfigureDevice(w.Name, config)
}

// Configure configures a Wireguard interface
// The interface must exist before calling this method (e.g. call interface.Create() before)
func (w *WGIface) Configure(privateKey string, port int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("configuring Wireguard interface %s", w.Name)

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
	}

	err = w.configureDevice(config)
	if err != nil {
		return fmt.Errorf("received error \"%v\" while configuring interface %s with port %d", err, w.Name, port)
	}
	return nil
}

// GetListenPort returns the listening port of the Wireguard endpoint
func (w *WGIface) GetListenPort() (*int, error) {
	log.Debugf("getting Wireguard listen port of interface %s", w.Name)

	//discover Wireguard current configuration
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()

	d, err := wg.Device(w.Name)
	if err != nil {
		return nil, err
	}
	log.Debugf("got Wireguard device listen port %s, %d", w.Name, d.ListenPort)

	return &d.ListenPort, nil
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
// Endpoint is optional
func (w *WGIface) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("updating interface %s peer %s: endpoint %s ", w.Name, peerKey, endpoint)

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
		return fmt.Errorf("received error \"%v\" while updating peer on interface %s with settings: allowed ips %s, endpoint %s", err, w.Name, allowedIps, endpoint.String())
	}
	return nil
}

// AddAllowedIP adds a prefix to the allowed IPs list of peer
func (w *WGIface) AddAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("adding allowed IP to interface %s and peer %s: allowed IP %s ", w.Name, peerKey, allowedIP)

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
		return fmt.Errorf("received error \"%v\" while adding allowed Ip to peer on interface %s with settings: allowed ips %s", err, w.Name, allowedIP)
	}
	return nil
}

// RemoveAllowedIP removes a prefix from the allowed IPs list of peer
func (w *WGIface) RemoveAllowedIP(peerKey string, allowedIP string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("removing allowed IP from interface %s and peer %s: allowed IP %s ", w.Name, peerKey, allowedIP)

	_, ipNet, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	existingPeer, err := getPeer(w.Name, peerKey)
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
		return fmt.Errorf("received error \"%v\" while removing allowed IP from peer on interface %s with settings: allowed ips %s", err, w.Name, allowedIP)
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

// RemovePeer removes a Wireguard Peer from the interface iface
func (w *WGIface) RemovePeer(peerKey string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Debugf("Removing peer %s from interface %s ", peerKey, w.Name)

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
		return fmt.Errorf("received error \"%v\" while removing peer %s from interface %s", err, peerKey, w.Name)
	}
	return nil
}
