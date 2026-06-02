//go:build (linux && !android) || freebsd

package configurer

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/monotime"
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

// SetPresharedKey sets the preshared key for a peer.
// If updateOnly is true, only updates the existing peer; if false, creates or updates.
func (c *KernelConfigurer) SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error {
	parsedPeerKey, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	cfg := buildPresharedKeyConfig(parsedPeerKey, psk, updateOnly)
	return c.configure(cfg)
}

func (c *KernelConfigurer) UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		ReplaceAllowedIPs: false,
		// don't replace allowed ips, wg will handle duplicated peer IP
		AllowedIPs:                  prefixesToIPNets(allowedIps),
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

func (c *KernelConfigurer) RemoveEndpointAddress(peerKey string) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	// Get the existing peer to preserve its allowed IPs
	existingPeer, err := c.getPeer(c.deviceName, peerKey)
	if err != nil {
		return fmt.Errorf("get peer: %w", err)
	}

	removePeerCfg := wgtypes.PeerConfig{
		PublicKey: peerKeyParsed,
		Remove:    true,
	}

	if err := c.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{removePeerCfg}}); err != nil {
		return fmt.Errorf(`error removing peer %s from interface %s: %w`, peerKey, c.deviceName, err)
	}

	//Re-add the peer without the endpoint but same AllowedIPs
	reAddPeerCfg := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		AllowedIPs:        existingPeer.AllowedIPs,
		ReplaceAllowedIPs: true,
	}

	if err := c.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{reAddPeerCfg}}); err != nil {
		return fmt.Errorf(
			`error re-adding peer %s to interface %s with allowed IPs %v: %w`,
			peerKey, c.deviceName, existingPeer.AllowedIPs, err,
		)
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

func (c *KernelConfigurer) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	ipNet := net.IPNet{
		IP:   allowedIP.Addr().AsSlice(),
		Mask: net.CIDRMask(allowedIP.Bits(), allowedIP.Addr().BitLen()),
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		UpdateOnly:        true,
		ReplaceAllowedIPs: false,
		AllowedIPs:        []net.IPNet{ipNet},
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

func (c *KernelConfigurer) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	ipNet := net.IPNet{
		IP:   allowedIP.Addr().AsSlice(),
		Mask: net.CIDRMask(allowedIP.Bits(), allowedIP.Addr().BitLen()),
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
	defer func() {
		if err := wg.Close(); err != nil {
			log.Errorf("Failed to close wgctrl client: %v", err)
		}
	}()

	// validate if device with name exists
	_, err = wg.Device(c.deviceName)
	if err != nil {
		return err
	}

	return wg.ConfigureDevice(c.deviceName, config)
}

func (c *KernelConfigurer) Close() {
}

func (c *KernelConfigurer) FullStats() (*Stats, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctl: %w", err)
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			log.Errorf("Got error while closing wgctl: %v", err)
		}
	}()

	wgDevice, err := wg.Device(c.deviceName)
	if err != nil {
		return nil, fmt.Errorf("get device %s: %w", c.deviceName, err)
	}
	fullStats := &Stats{
		DeviceName: wgDevice.Name,
		PublicKey:  wgDevice.PublicKey.String(),
		ListenPort: wgDevice.ListenPort,
		FWMark:     wgDevice.FirewallMark,
		Peers:      []Peer{},
	}

	for _, p := range wgDevice.Peers {
		peer := Peer{
			PublicKey:     p.PublicKey.String(),
			AllowedIPs:    p.AllowedIPs,
			TxBytes:       p.TransmitBytes,
			RxBytes:       p.ReceiveBytes,
			LastHandshake: p.LastHandshakeTime,
			PresharedKey:  [32]byte(p.PresharedKey),
		}
		if p.Endpoint != nil {
			peer.Endpoint = *p.Endpoint
		}
		fullStats.Peers = append(fullStats.Peers, peer)
	}
	return fullStats, nil
}

func (c *KernelConfigurer) GetStats() (map[string]WGStats, error) {
	stats := make(map[string]WGStats)
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctl: %w", err)
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			log.Errorf("Got error while closing wgctl: %v", err)
		}
	}()

	wgDevice, err := wg.Device(c.deviceName)
	if err != nil {
		return nil, fmt.Errorf("get device %s: %w", c.deviceName, err)
	}

	for _, peer := range wgDevice.Peers {
		stats[peer.PublicKey.String()] = WGStats{
			LastHandshake: peer.LastHandshakeTime,
			TxBytes:       peer.TransmitBytes,
			RxBytes:       peer.ReceiveBytes,
		}
	}
	return stats, nil
}

func (c *KernelConfigurer) LastActivities() map[string]monotime.Time {
	return nil
}
