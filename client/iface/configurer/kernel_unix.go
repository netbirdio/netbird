//go:build (linux && !android) || freebsd

package configurer

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type KernelConfigurer struct {
	deviceName string
}

func NewKernelConfigurer(deviceName string) *KernelConfigurer {
	return &KernelConfigurer{
		deviceName: deviceName,
	}
}

func (c *KernelConfigurer) ConfigureInterface(privateKey string, port int) error {
	log.Debugf("adding Wireguard private key")
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return err
	}
	fwmark := getFwmark()
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

func (c *KernelConfigurer) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	// parse allowed ips
	_, ipNet, err := net.ParseCIDR(allowedIps)
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		ReplaceAllowedIPs: false,
		// don't replace allowed ips, wg will handle duplicated peer IP
		AllowedIPs:                  []net.IPNet{*ipNet},
		PersistentKeepaliveInterval: &keepAlive,
		Endpoint:                    endpoint,
		PresharedKey:                preSharedKey,
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

func (c *KernelConfigurer) RemovePeer(peerKey string) error {
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

func (c *KernelConfigurer) AddAllowedIP(peerKey string, allowedIP string) error {
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

func (c *KernelConfigurer) RemoveAllowedIP(peerKey string, allowedIP string) error {
	_, ipNet, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return fmt.Errorf("parse allowed IP: %w", err)
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}

	existingPeer, err := c.getPeer(c.deviceName, peerKey)
	if err != nil {
		return fmt.Errorf("get peer: %w", err)
	}

	newAllowedIPs := existingPeer.AllowedIPs

	for i, existingAllowedIP := range existingPeer.AllowedIPs {
		if existingAllowedIP.String() == ipNet.String() {
			newAllowedIPs = append(existingPeer.AllowedIPs[:i], existingPeer.AllowedIPs[i+1:]...) //nolint:gocritic
			break
		}
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
		return fmt.Errorf("remove allowed IP %s on interface %s: %w", allowedIP, c.deviceName, err)
	}
	return nil
}

func (c *KernelConfigurer) getPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return wgtypes.Peer{}, fmt.Errorf("wgctl: %w", err)
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			log.Errorf("Got error while closing wgctl: %v", err)
		}
	}()

	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return wgtypes.Peer{}, fmt.Errorf("get device %s: %w", ifaceName, err)
	}
	for _, peer := range wgDevice.Peers {
		if peer.PublicKey.String() == peerPubKey {
			return peer, nil
		}
	}
	return wgtypes.Peer{}, ErrPeerNotFound
}

func (c *KernelConfigurer) configure(config wgtypes.Config) error {
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

	return wg.ConfigureDevice(c.deviceName, config)
}

func (c *KernelConfigurer) Close() {
}

func (c *KernelConfigurer) GetStats(peerKey string) (WGStats, error) {
	peer, err := c.getPeer(c.deviceName, peerKey)
	if err != nil {
		return WGStats{}, fmt.Errorf("get wireguard stats: %w", err)
	}
	return WGStats{
		LastHandshake: peer.LastHandshakeTime,
		TxBytes:       peer.TransmitBytes,
		RxBytes:       peer.ReceiveBytes,
	}, nil
}
