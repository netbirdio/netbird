package configurer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/monotime"
)

const (
	privateKey                 = "private_key"
	ipcKeyLastHandshakeTimeSec = "last_handshake_time_sec"
	ipcKeyTxBytes              = "tx_bytes"
	ipcKeyRxBytes              = "rx_bytes"
	allowedIP                  = "allowed_ip"
	endpoint                   = "endpoint"
	fwmark                     = "fwmark"
	listenPort                 = "listen_port"
	publicKey                  = "public_key"
	presharedKey               = "preshared_key"
)

var ErrAllowedIPNotFound = fmt.Errorf("allowed IP not found")

type WGUSPConfigurer struct {
	device           *device.Device
	deviceName       string
	activityRecorder *bind.ActivityRecorder

	uapiListener net.Listener
}

func NewUSPConfigurer(device *device.Device, deviceName string, activityRecorder *bind.ActivityRecorder) *WGUSPConfigurer {
	wgCfg := &WGUSPConfigurer{
		device:           device,
		deviceName:       deviceName,
		activityRecorder: activityRecorder,
	}
	wgCfg.startUAPI()
	return wgCfg
}

func (c *WGUSPConfigurer) ConfigureInterface(privateKey string, port int) error {
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

	return c.device.IpcSet(toWgUserspaceString(config))
}

// SetPresharedKey sets the preshared key for a peer.
// If updateOnly is true, only updates the existing peer; if false, creates or updates.
func (c *WGUSPConfigurer) SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error {
	parsedPeerKey, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	cfg := buildPresharedKeyConfig(parsedPeerKey, psk, updateOnly)
	return c.device.IpcSet(toWgUserspaceString(cfg))
}

func (c *WGUSPConfigurer) UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
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
		PresharedKey:                preSharedKey,
		Endpoint:                    endpoint,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	if ipcErr := c.device.IpcSet(toWgUserspaceString(config)); ipcErr != nil {
		return ipcErr
	}

	if endpoint != nil {
		addr, err := netip.ParseAddr(endpoint.IP.String())
		if err != nil {
			return fmt.Errorf("failed to parse endpoint address: %w", err)
		}
		addrPort := netip.AddrPortFrom(addr, uint16(endpoint.Port))
		c.activityRecorder.UpsertAddress(peerKey, addrPort)
	}
	return nil
}

func (c *WGUSPConfigurer) RemoveEndpointAddress(peerKey string) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}

	ipcStr, err := c.device.IpcGet()
	if err != nil {
		return fmt.Errorf("get IPC config: %w", err)
	}

	// Parse current status to get allowed IPs for the peer
	stats, err := parseStatus(c.deviceName, ipcStr)
	if err != nil {
		return fmt.Errorf("parse IPC config: %w", err)
	}

	var allowedIPs []net.IPNet
	found := false
	for _, peer := range stats.Peers {
		if peer.PublicKey == peerKey {
			allowedIPs = peer.AllowedIPs
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("peer %s not found", peerKey)
	}

	// remove the peer from the WireGuard configuration
	peer := wgtypes.PeerConfig{
		PublicKey: peerKeyParsed,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	if ipcErr := c.device.IpcSet(toWgUserspaceString(config)); ipcErr != nil {
		return fmt.Errorf("failed to remove peer: %s", ipcErr)
	}

	// Build the peer config
	peer = wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		ReplaceAllowedIPs: true,
		AllowedIPs:        allowedIPs,
	}

	config = wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	if err := c.device.IpcSet(toWgUserspaceString(config)); err != nil {
		return fmt.Errorf("remove endpoint address: %w", err)
	}

	return nil
}

func (c *WGUSPConfigurer) RemovePeer(peerKey string) error {
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
	ipcErr := c.device.IpcSet(toWgUserspaceString(config))

	c.activityRecorder.Remove(peerKey)
	return ipcErr
}

func (c *WGUSPConfigurer) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
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

	return c.device.IpcSet(toWgUserspaceString(config))
}

func (c *WGUSPConfigurer) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	ipc, err := c.device.IpcGet()
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	hexKey := hex.EncodeToString(peerKeyParsed[:])

	lines := strings.Split(ipc, "\n")

	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		UpdateOnly:        true,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{},
	}

	foundPeer := false
	removedAllowedIP := false
	ip := allowedIP.String()

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// If we're within the details of the found peer and encounter another public key,
		// this means we're starting another peer's details. So, reset the flag.
		if strings.HasPrefix(line, "public_key=") && foundPeer {
			foundPeer = false
		}

		// Identify the peer with the specific public key
		if line == fmt.Sprintf("public_key=%s", hexKey) {
			foundPeer = true
		}

		// If we're within the details of the found peer and find the specific allowed IP, skip this line
		if foundPeer && line == "allowed_ip="+ip {
			removedAllowedIP = true
			continue
		}

		// Append the line to the output string
		if foundPeer && strings.HasPrefix(line, "allowed_ip=") {
			allowedIPStr := strings.TrimPrefix(line, "allowed_ip=")
			_, ipNet, err := net.ParseCIDR(allowedIPStr)
			if err != nil {
				return err
			}
			peer.AllowedIPs = append(peer.AllowedIPs, *ipNet)
		}
	}

	if !removedAllowedIP {
		return ErrAllowedIPNotFound
	}
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	return c.device.IpcSet(toWgUserspaceString(config))
}

func (c *WGUSPConfigurer) FullStats() (*Stats, error) {
	ipcStr, err := c.device.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("IpcGet failed: %w", err)
	}

	return parseStatus(c.deviceName, ipcStr)
}

func (c *WGUSPConfigurer) LastActivities() map[string]monotime.Time {
	return c.activityRecorder.GetLastActivities()
}

// startUAPI starts the UAPI listener for managing the WireGuard interface via external tool
func (t *WGUSPConfigurer) startUAPI() {
	var err error
	t.uapiListener, err = openUAPI(t.deviceName)
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
				t.device.IpcHandle(uapiConn)
			}()
		}
	}(t.uapiListener)
}

func (t *WGUSPConfigurer) Close() {
	if t.uapiListener != nil {
		err := t.uapiListener.Close()
		if err != nil {
			log.Errorf("failed to close uapi listener: %v", err)
		}
	}

	if runtime.GOOS == "linux" {
		sockPath := "/var/run/wireguard/" + t.deviceName + ".sock"
		if _, statErr := os.Stat(sockPath); statErr == nil {
			_ = os.Remove(sockPath)
		}
	}
}

func (t *WGUSPConfigurer) GetStats() (map[string]WGStats, error) {
	ipc, err := t.device.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("ipc get: %w", err)
	}

	return parseTransfers(ipc)
}

func parseTransfers(ipc string) (map[string]WGStats, error) {
	stats := make(map[string]WGStats)
	var (
		currentKey   string
		currentStats WGStats
		hasPeer      bool
	)
	lines := strings.Split(ipc, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// If we're within the details of the found peer and encounter another public key,
		// this means we're starting another peer's details. So, stop.
		if strings.HasPrefix(line, "public_key=") {
			peerID := strings.TrimPrefix(line, "public_key=")
			h, err := hex.DecodeString(peerID)
			if err != nil {
				return nil, fmt.Errorf("decode peerID: %w", err)
			}
			currentKey = base64.StdEncoding.EncodeToString(h)
			currentStats = WGStats{} // Reset stats for the new peer
			hasPeer = true
			stats[currentKey] = currentStats
			continue
		}

		if !hasPeer {
			continue
		}

		key := strings.SplitN(line, "=", 2)
		if len(key) != 2 {
			continue
		}
		switch key[0] {
		case ipcKeyLastHandshakeTimeSec:
			hs, err := toLastHandshake(key[1])
			if err != nil {
				return nil, err
			}
			currentStats.LastHandshake = hs
			stats[currentKey] = currentStats
		case ipcKeyRxBytes:
			rxBytes, err := toBytes(key[1])
			if err != nil {
				return nil, fmt.Errorf("parse rx_bytes: %w", err)
			}
			currentStats.RxBytes = rxBytes
			stats[currentKey] = currentStats
		case ipcKeyTxBytes:
			TxBytes, err := toBytes(key[1])
			if err != nil {
				return nil, fmt.Errorf("parse tx_bytes: %w", err)
			}
			currentStats.TxBytes = TxBytes
			stats[currentKey] = currentStats
		}
	}

	return stats, nil
}

func toWgUserspaceString(wgCfg wgtypes.Config) string {
	var sb strings.Builder
	if wgCfg.PrivateKey != nil {
		hexKey := hex.EncodeToString(wgCfg.PrivateKey[:])
		sb.WriteString(fmt.Sprintf("private_key=%s\n", hexKey))
	}

	if wgCfg.ListenPort != nil {
		sb.WriteString(fmt.Sprintf("listen_port=%d\n", *wgCfg.ListenPort))
	}

	if wgCfg.ReplacePeers {
		sb.WriteString("replace_peers=true\n")
	}

	if wgCfg.FirewallMark != nil {
		sb.WriteString(fmt.Sprintf("fwmark=%d\n", *wgCfg.FirewallMark))
	}

	for _, p := range wgCfg.Peers {
		hexKey := hex.EncodeToString(p.PublicKey[:])
		sb.WriteString(fmt.Sprintf("public_key=%s\n", hexKey))

		if p.Remove {
			sb.WriteString("remove=true\n")
		}

		if p.UpdateOnly {
			sb.WriteString("update_only=true\n")
		}

		if p.PresharedKey != nil {
			preSharedHexKey := hex.EncodeToString(p.PresharedKey[:])
			sb.WriteString(fmt.Sprintf("preshared_key=%s\n", preSharedHexKey))
		}

		if p.Endpoint != nil {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", p.Endpoint.String()))
		}

		if p.PersistentKeepaliveInterval != nil {
			sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds())))
		}

		if p.ReplaceAllowedIPs {
			sb.WriteString("replace_allowed_ips=true\n")
		}

		for _, aip := range p.AllowedIPs {
			sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", aip.String()))
		}
	}
	return sb.String()
}

func toLastHandshake(stringVar string) (time.Time, error) {
	sec, err := strconv.ParseInt(stringVar, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse handshake sec: %w", err)
	}

	// If sec is 0 (Unix epoch), return zero time instead
	// This indicates no handshake has occurred
	if sec == 0 {
		return time.Time{}, nil
	}

	return time.Unix(sec, 0), nil
}

func toBytes(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func getFwmark() int {
	if nbnet.AdvancedRouting() && runtime.GOOS == "linux" {
		return nbnet.ControlPlaneMark
	}
	return 0
}

func hexToWireguardKey(hexKey string) (wgtypes.Key, error) {
	// Decode hex string to bytes
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to decode hex key: %w", err)
	}

	// Check if we have the right number of bytes (WireGuard keys are 32 bytes)
	if len(keyBytes) != 32 {
		return wgtypes.Key{}, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(keyBytes))
	}

	// Convert to wgtypes.Key
	var key wgtypes.Key
	copy(key[:], keyBytes)

	return key, nil
}

func parseStatus(deviceName, ipcStr string) (*Stats, error) {
	stats := &Stats{DeviceName: deviceName}
	var currentPeer *Peer
	for _, line := range strings.Split(strings.TrimSpace(ipcStr), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := parts[1]

		switch key {
		case privateKey:
			key, err := hexToWireguardKey(val)
			if err != nil {
				log.Errorf("failed to parse private key: %v", err)
				continue
			}
			stats.PublicKey = key.PublicKey().String()
		case publicKey:
			// Save previous peer
			if currentPeer != nil {
				stats.Peers = append(stats.Peers, *currentPeer)
			}
			key, err := hexToWireguardKey(val)
			if err != nil {
				log.Errorf("failed to parse public key: %v", err)
				continue
			}
			currentPeer = &Peer{
				PublicKey: key.String(),
			}
		case listenPort:
			if port, err := strconv.Atoi(val); err == nil {
				stats.ListenPort = port
			}
		case fwmark:
			if fwmark, err := strconv.Atoi(val); err == nil {
				stats.FWMark = fwmark
			}
		case endpoint:
			if currentPeer == nil {
				continue
			}

			host, portStr, err := net.SplitHostPort(val)
			if err != nil {
				log.Errorf("failed to parse endpoint: %v", err)
				continue
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				log.Errorf("failed to parse endpoint port: %v", err)
				continue
			}
			currentPeer.Endpoint = net.UDPAddr{
				IP:   net.ParseIP(host),
				Port: port,
			}
		case allowedIP:
			if currentPeer == nil {
				continue
			}
			_, ipnet, err := net.ParseCIDR(val)
			if err == nil {
				currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, *ipnet)
			}
		case ipcKeyTxBytes:
			if currentPeer == nil {
				continue
			}
			rxBytes, err := toBytes(val)
			if err != nil {
				continue
			}
			currentPeer.TxBytes = rxBytes
		case ipcKeyRxBytes:
			if currentPeer == nil {
				continue
			}
			rxBytes, err := toBytes(val)
			if err != nil {
				continue
			}
			currentPeer.RxBytes = rxBytes

		case ipcKeyLastHandshakeTimeSec:
			if currentPeer == nil {
				continue
			}

			ts, err := toLastHandshake(val)
			if err != nil {
				continue
			}
			currentPeer.LastHandshake = ts
		case presharedKey:
			if currentPeer == nil {
				continue
			}
			if val != "" && val != "0000000000000000000000000000000000000000000000000000000000000000" {
				if pskKey, err := hexToWireguardKey(val); err == nil {
					currentPeer.PresharedKey = [32]byte(pskKey)
				}
			}
		}
	}
	if currentPeer != nil {
		stats.Peers = append(stats.Peers, *currentPeer)
	}
	return stats, nil
}
