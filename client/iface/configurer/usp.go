package configurer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbnet "github.com/netbirdio/netbird/util/net"
)

const (
	ipcKeyLastHandshakeTimeSec  = "last_handshake_time_sec"
	ipcKeyLastHandshakeTimeNsec = "last_handshake_time_nsec"
	ipcKeyTxBytes               = "tx_bytes"
	ipcKeyRxBytes               = "rx_bytes"
)

var ErrAllowedIPNotFound = fmt.Errorf("allowed IP not found")

type WGUSPConfigurer struct {
	device     *device.Device
	deviceName string

	uapiListener net.Listener
}

func NewUSPConfigurer(device *device.Device, deviceName string) *WGUSPConfigurer {
	wgCfg := &WGUSPConfigurer{
		device:     device,
		deviceName: deviceName,
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

func (c *WGUSPConfigurer) UpdatePeer(peerKey string, allowedIps []net.IPNet, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}
	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		ReplaceAllowedIPs: false,
		// don't replace allowed ips, wg will handle duplicated peer IP
		AllowedIPs:                  allowedIps,
		PersistentKeepaliveInterval: &keepAlive,
		PresharedKey:                preSharedKey,
		Endpoint:                    endpoint,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	return c.device.IpcSet(toWgUserspaceString(config))
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
	return c.device.IpcSet(toWgUserspaceString(config))
}

func (c *WGUSPConfigurer) AddAllowedIP(peerKey string, allowedIP string) error {
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

	return c.device.IpcSet(toWgUserspaceString(config))
}

func (c *WGUSPConfigurer) RemoveAllowedIP(peerKey string, ip string) error {
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
			allowedIP := strings.TrimPrefix(line, "allowed_ip=")
			_, ipNet, err := net.ParseCIDR(allowedIP)
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

		if p.PresharedKey != nil {
			preSharedHexKey := hex.EncodeToString(p.PresharedKey[:])
			sb.WriteString(fmt.Sprintf("preshared_key=%s\n", preSharedHexKey))
		}

		if p.Remove {
			sb.WriteString("remove=true")
		}

		if p.ReplaceAllowedIPs {
			sb.WriteString("replace_allowed_ips=true\n")
		}

		for _, aip := range p.AllowedIPs {
			sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", aip.String()))
		}

		if p.Endpoint != nil {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", p.Endpoint.String()))
		}

		if p.PersistentKeepaliveInterval != nil {
			sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds())))
		}
	}
	return sb.String()
}

func toLastHandshake(stringVar string) (time.Time, error) {
	sec, err := strconv.ParseInt(stringVar, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse handshake sec: %w", err)
	}
	return time.Unix(sec, 0), nil
}

func toBytes(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func getFwmark() int {
	if nbnet.AdvancedRouting() {
		return nbnet.ControlPlaneMark
	}
	return 0
}
