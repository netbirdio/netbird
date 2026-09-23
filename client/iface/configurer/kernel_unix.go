//go:build (linux && !android) || freebsd

package configurer

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/monotime"
)

type KernelConfigurer struct {
	deviceName string
	statsCache *statsCache
	allowedIPs *allowedIPStore
}

func NewKernelConfigurer(deviceName string) *KernelConfigurer {
	c := &KernelConfigurer{
		deviceName: deviceName,
		allowedIPs: newAllowedIPStore(),
	}
	c.statsCache = newStatsCache(statsCacheTTL, c.fetchStats)
	return c
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

	c.allowedIPs.reset()
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

	c.allowedIPs.add(peerKey, allowedIps)
	return nil
}

// RemoveEndpointAddress clears the endpoint of a peer while keeping it configured.
// Neither the netlink API nor the userspace one can clear an endpoint in place, so the peer
// is removed and re-added with the allowed IPs it already had.
func (c *KernelConfigurer) RemoveEndpointAddress(peerKey string) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	allowedIPs, err := c.peerAllowedIPs(peerKey)
	if err != nil {
		return err
	}

	removePeerCfg := wgtypes.PeerConfig{
		PublicKey: peerKeyParsed,
		Remove:    true,
	}

	if err := c.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{removePeerCfg}}); err != nil {
		return fmt.Errorf("remove peer %s from interface %s: %w", peerKey, c.deviceName, err)
	}

	reAddPeerCfg := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		AllowedIPs:        prefixesToIPNets(allowedIPs),
		ReplaceAllowedIPs: true,
	}

	if err := c.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{reAddPeerCfg}}); err != nil {
		c.allowedIPs.forget(peerKey)
		return fmt.Errorf(
			"re-add peer %s to interface %s with allowed IPs %v: %w",
			peerKey, c.deviceName, allowedIPs, err,
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

	c.allowedIPs.forget(peerKey)
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

	c.allowedIPs.add(peerKey, []netip.Prefix{allowedIP})
	return nil
}

func (c *KernelConfigurer) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}

	currentAllowedIPs, err := c.peerAllowedIPs(peerKey)
	if err != nil {
		return err
	}

	idx := slices.Index(currentAllowedIPs, normalizePrefix(allowedIP))
	if idx < 0 {
		return nil
	}
	newAllowedIPs := slices.Delete(currentAllowedIPs, idx, idx+1)

	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		UpdateOnly:        true,
		ReplaceAllowedIPs: true,
		AllowedIPs:        prefixesToIPNets(newAllowedIPs),
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	if err := c.configure(config); err != nil {
		return fmt.Errorf("remove allowed IP %s on interface %s: %w", allowedIP, c.deviceName, err)
	}

	c.allowedIPs.set(peerKey, newAllowedIPs)
	return nil
}

// peerAllowedIPs returns the allowed IPs configured for a peer, reading them from the device
// only for a peer the store has not seen. Dumping the device costs a netlink round trip
// proportional to the whole network map, and this runs on every relay and ICE transition.
func (c *KernelConfigurer) peerAllowedIPs(peerKey string) ([]netip.Prefix, error) {
	if prefixes, ok := c.allowedIPs.get(peerKey); ok {
		return prefixes, nil
	}

	existingPeer, err := c.getPeer(c.deviceName, peerKey)
	if err != nil {
		return nil, fmt.Errorf("get peer: %w", err)
	}

	prefixes := ipNetsToPrefixes(existingPeer.AllowedIPs)
	c.allowedIPs.set(peerKey, prefixes)
	return prefixes, nil
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
	return c.statsCache.get()
}

func (c *KernelConfigurer) LastActivities() map[string]monotime.Time {
	return nil
}

func (c *KernelConfigurer) fetchStats() (map[string]WGStats, error) {
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
