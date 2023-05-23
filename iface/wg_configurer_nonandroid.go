//go:build !android

package iface

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wGConfigurer struct {
	deviceName string
}

func newWGConfigurer(deviceName string) wGConfigurer {
	return wGConfigurer{
		deviceName: deviceName,
	}
}

func (c *wGConfigurer) configureInterface(privateKey string, port int) error {
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

	err = c.configure(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while configuring interface %s with port %d`, err, c.deviceName, port)
	}
	return nil
}

func (c *wGConfigurer) updatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
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
	err = c.configure(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while updating peer on interface %s with settings: allowed ips %s, endpoint %s`, err, c.deviceName, allowedIps, endpoint.String())
	}
	return nil
}

func (c *wGConfigurer) removePeer(peerKey string) error {
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
	err = c.configure(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while removing peer %s from interface %s`, err, peerKey, c.deviceName)
	}
	return nil
}

func (c *wGConfigurer) addAllowedIP(peerKey string, allowedIP string) error {
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
	err = c.configure(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while adding allowed Ip to peer on interface %s with settings: allowed ips %s`, err, c.deviceName, allowedIP)
	}
	return nil
}

func (c *wGConfigurer) removeAllowedIP(peerKey string, allowedIP string) error {
	_, ipNet, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	existingPeer, err := c.getPeer(c.deviceName, peerKey)
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
	err = c.configure(config)
	if err != nil {
		return fmt.Errorf(`received error "%w" while removing allowed IP from peer on interface %s with settings: allowed ips %s`, err, c.deviceName, allowedIP)
	}
	return nil
}

func (c *wGConfigurer) getPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
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

func (c *wGConfigurer) configure(config wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	// validate if device with name exists
	_, err = wg.Device(c.deviceName)
	if err != nil {
		return err
	}
	log.Tracef("got Wireguard device %s", c.deviceName)

	return wg.ConfigureDevice(c.deviceName, config)
}
