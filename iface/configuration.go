package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"time"
)

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
		ListenPort:   &port,
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

// RemovePeer removes a Wireguard Peer from the interface iface
func (w *WGIface) RemovePeer(peerKey string) error {
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
