package configurer

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/monotime"
)

var ErrAllowedIPNotFound = fmt.Errorf("allowed IP not found")

type WGUSPConfigurer struct {
	device           *device.Device
	deviceName       string
	activityRecorder *bind.ActivityRecorder
	statsCache       *statsCache

	uapiListener net.Listener
}

// NewUSPConfigurer creates a userspace configurer and starts its UAPI listener.
func NewUSPConfigurer(device *device.Device, deviceName string, activityRecorder *bind.ActivityRecorder) *WGUSPConfigurer {
	wgCfg := NewUSPConfigurerNoUAPI(device, deviceName, activityRecorder)
	wgCfg.startUAPI()
	return wgCfg
}

// NewUSPConfigurerNoUAPI creates a userspace configurer without a UAPI listener.
func NewUSPConfigurerNoUAPI(device *device.Device, deviceName string, activityRecorder *bind.ActivityRecorder) *WGUSPConfigurer {
	wgCfg := &WGUSPConfigurer{
		device:           device,
		deviceName:       deviceName,
		activityRecorder: activityRecorder,
	}
	wgCfg.statsCache = newStatsCache(statsCacheTTL, wgCfg.fetchStats)
	return wgCfg
}

// ConfigureInterface sets the device key, port and firewall mark, replacing all peers.
func (c *WGUSPConfigurer) ConfigureInterface(privateKey string, port int) error {
	log.Debugf("adding Wireguard private key")
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return err
	}
	if port < 0 || port > math.MaxUint16 {
		return fmt.Errorf("invalid listen port %d", port)
	}

	if err := c.device.SetPrivateKey(device.NoisePrivateKey(key)); err != nil {
		return fmt.Errorf("set private key: %w", err)
	}
	if err := c.device.SetListenPort(uint16(port)); err != nil {
		return fmt.Errorf("set listen port %d: %w", port, err)
	}
	c.device.RemoveAllPeers()
	if err := c.device.BindSetMark(uint32(getFwmark())); err != nil {
		return fmt.Errorf("set fwmark: %w", err)
	}
	return nil
}

// SetPresharedKey sets the preshared key for a peer.
// If updateOnly is true, only updates the existing peer; if false, creates or updates.
func (c *WGUSPConfigurer) SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error {
	parsedPeerKey, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	presharedKey := device.NoisePresharedKey(psk)
	return c.device.ConfigurePeer(device.NoisePublicKey(parsedPeerKey), device.PeerConfig{
		PresharedKey: &presharedKey,
		UpdateOnly:   updateOnly,
	})
}

// UpdatePeer creates or updates a peer, merging allowed IPs with its existing set.
func (c *WGUSPConfigurer) UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	prefixes, err := validPrefixes(allowedIps)
	if err != nil {
		return err
	}

	cfg := device.PeerConfig{
		PersistentKeepalive: &keepAlive,
		AllowedIPs:          prefixes,
	}

	var addrPort netip.AddrPort
	if endpoint != nil {
		addr, ok := netip.AddrFromSlice(endpoint.IP)
		if !ok {
			return fmt.Errorf("parse endpoint address %v", endpoint.IP)
		}
		addrPort = netip.AddrPortFrom(addr.Unmap(), uint16(endpoint.Port))
		cfg.Endpoint = &bind.Endpoint{AddrPort: addrPort}
	}

	if preSharedKey != nil {
		psk := device.NoisePresharedKey(*preSharedKey)
		cfg.PresharedKey = &psk
	}

	if err := c.device.ConfigurePeer(device.NoisePublicKey(peerKeyParsed), cfg); err != nil {
		return fmt.Errorf("configure peer: %w", err)
	}

	if endpoint != nil {
		c.activityRecorder.UpsertAddress(peerKey, addrPort)
	}
	return nil
}

// RemoveEndpointAddress clears the endpoint of a peer while keeping it configured.
// The session is reset and the keepalive is switched off until the next endpoint arrives.
func (c *WGUSPConfigurer) RemoveEndpointAddress(peerKey string) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}

	peer := c.device.LookupPeer(device.NoisePublicKey(peerKeyParsed))
	if peer == nil {
		return ErrPeerNotFound
	}

	peer.ClearEndpoint()
	peer.ZeroAndFlushAll()

	var noKeepAlive time.Duration
	if err := c.device.ConfigurePeer(device.NoisePublicKey(peerKeyParsed), device.PeerConfig{
		PersistentKeepalive: &noKeepAlive,
		UpdateOnly:          true,
	}); err != nil {
		return fmt.Errorf("disable keepalive: %w", err)
	}
	return nil
}

// RemovePeer removes a peer and clears its activity record.
func (c *WGUSPConfigurer) RemovePeer(peerKey string) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	c.device.RemovePeer(device.NoisePublicKey(peerKeyParsed))
	c.activityRecorder.Remove(peerKey)
	return nil
}

// AddAllowedIP adds a prefix to an existing peer; an absent peer is a silent no-op.
func (c *WGUSPConfigurer) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	if !allowedIP.IsValid() {
		return fmt.Errorf("invalid allowed IP %v", allowedIP)
	}

	peer := c.device.LookupPeer(device.NoisePublicKey(peerKeyParsed))
	if peer == nil {
		return nil
	}

	peer.AddAllowedIP(normalizePrefix(allowedIP))
	return nil
}

// RemoveAllowedIP removes a prefix while preserving the peer's other allowed IPs.
// It returns ErrAllowedIPNotFound if the prefix is not assigned to the peer.
func (c *WGUSPConfigurer) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}
	if !allowedIP.IsValid() {
		return ErrAllowedIPNotFound
	}

	peer := c.device.LookupPeer(device.NoisePublicKey(peerKeyParsed))
	if peer == nil {
		return ErrPeerNotFound
	}

	if !peer.RemoveAllowedIP(normalizePrefix(allowedIP)) {
		return ErrAllowedIPNotFound
	}
	return nil
}

func (c *WGUSPConfigurer) FullStats() (*Stats, error) {
	peers := c.device.Peers()
	stats := &Stats{
		DeviceName: c.deviceName,
		PublicKey:  wgtypes.Key(c.device.PublicKey()).String(),
		ListenPort: int(c.device.ListenPort()),
		FWMark:     int(c.device.FirewallMark()),
		Peers:      make([]Peer, 0, len(peers)),
	}
	for _, peer := range peers {
		stats.Peers = append(stats.Peers, peerStats(peer))
	}
	return stats, nil
}

func (c *WGUSPConfigurer) LastActivities() map[string]monotime.Time {
	return c.activityRecorder.GetLastActivities()
}

func (c *WGUSPConfigurer) GetStats() (map[string]WGStats, error) {
	return c.statsCache.get()
}

func (c *WGUSPConfigurer) Close() {
	if c.uapiListener != nil {
		err := c.uapiListener.Close()
		if err != nil {
			log.Errorf("failed to close uapi listener: %v", err)
		}
	}

	if runtime.GOOS == "linux" {
		sockPath := "/var/run/wireguard/" + c.deviceName + ".sock"
		if _, statErr := os.Stat(sockPath); statErr == nil {
			_ = os.Remove(sockPath)
		}
	}
}

// startUAPI starts the UAPI listener for managing the WireGuard interface via external tool
func (c *WGUSPConfigurer) startUAPI() {
	var err error
	c.uapiListener, err = openUAPI(c.deviceName)
	if err != nil {
		log.Errorf("failed to open uapi listener: %v", err)
		return
	}

	go func(uapi net.Listener) {
		for {
			uapiConn, uapiErr := uapi.Accept()
			if uapiErr != nil {
				log.Tracef("%s", uapiErr)
				return
			}
			go func() {
				c.device.IpcHandle(uapiConn)
			}()
		}
	}(c.uapiListener)
}

func (c *WGUSPConfigurer) fetchStats() (map[string]WGStats, error) {
	peers := c.device.Peers()
	stats := make(map[string]WGStats, len(peers))
	for _, peer := range peers {
		stats[wgtypes.Key(peer.PublicKey()).String()] = WGStats{
			LastHandshake: peer.LastHandshake(),
			TxBytes:       int64(peer.TxBytes()),
			RxBytes:       int64(peer.RxBytes()),
		}
	}
	return stats, nil
}

func peerStats(peer *device.Peer) Peer {
	stats := Peer{
		PublicKey:     wgtypes.Key(peer.PublicKey()).String(),
		AllowedIPs:    prefixesToIPNets(peer.AllowedIPs()),
		TxBytes:       int64(peer.TxBytes()),
		RxBytes:       int64(peer.RxBytes()),
		LastHandshake: peer.LastHandshake(),
		PresharedKey:  [32]byte(peer.PresharedKey()),
	}
	if addrPort, ok := endpointAddrPort(peer.Endpoint()); ok {
		stats.Endpoint = net.UDPAddr{IP: addrPort.Addr().AsSlice(), Port: int(addrPort.Port())}
	}
	return stats
}

func endpointAddrPort(endpoint wgconn.Endpoint) (netip.AddrPort, bool) {
	if endpoint == nil {
		return netip.AddrPort{}, false
	}
	if ep, ok := endpoint.(*bind.Endpoint); ok {
		return ep.AddrPort, true
	}
	addrPort, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

func validPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("invalid allowed IP %v", prefix)
		}
	}
	return normalizePrefixes(prefixes), nil
}

func getFwmark() int {
	if nbnet.AdvancedRouting() && runtime.GOOS == "linux" {
		return int(nbnet.ControlPlaneMark)
	}
	return 0
}
