package iface

import (
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

type wgUSPConfigurer struct {
	device     *device.Device
	deviceName string

	uapiListener net.Listener
}

func newWGUSPConfigurer(device *device.Device, deviceName string) wgConfigurer {
	wgCfg := &wgUSPConfigurer{
		device:     device,
		deviceName: deviceName,
	}
	wgCfg.startUAPI()
	return wgCfg
}

func (c *wgUSPConfigurer) configureInterface(privateKey string, port int) error {
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

func (c *wgUSPConfigurer) updatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
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

	return c.device.IpcSet(toWgUserspaceString(config))
}

func (c *wgUSPConfigurer) removePeer(peerKey string) error {
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

func (c *wgUSPConfigurer) addAllowedIP(peerKey string, allowedIP string) error {
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

func (c *wgUSPConfigurer) removeAllowedIP(peerKey string, ip string) error {
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
		return fmt.Errorf("allowedIP not found")
	}
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	return c.device.IpcSet(toWgUserspaceString(config))
}

// startUAPI starts the UAPI listener for managing the WireGuard interface via external tool
func (t *wgUSPConfigurer) startUAPI() {
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

func (t *wgUSPConfigurer) close() {
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

func (t *wgUSPConfigurer) getStats(peerKey string) (WGStats, error) {
	ipc, err := t.device.IpcGet()
	if err != nil {
		return WGStats{}, fmt.Errorf("ipc get: %w", err)
	}

	stats, err := findPeerInfo(ipc, peerKey, []string{
		"last_handshake_time_sec",
		"last_handshake_time_nsec",
		"tx_bytes",
		"rx_bytes",
	})
	if err != nil {
		return WGStats{}, fmt.Errorf("find peer info: %w", err)
	}

	sec, err := strconv.ParseInt(stats["last_handshake_time_sec"], 10, 64)
	if err != nil {
		return WGStats{}, fmt.Errorf("parse handshake sec: %w", err)
	}
	nsec, err := strconv.ParseInt(stats["last_handshake_time_nsec"], 10, 64)
	if err != nil {
		return WGStats{}, fmt.Errorf("parse handshake nsec: %w", err)
	}
	txBytes, err := strconv.ParseInt(stats["tx_bytes"], 10, 64)
	if err != nil {
		return WGStats{}, fmt.Errorf("parse tx_bytes: %w", err)
	}
	rxBytes, err := strconv.ParseInt(stats["rx_bytes"], 10, 64)
	if err != nil {
		return WGStats{}, fmt.Errorf("parse rx_bytes: %w", err)
	}

	return WGStats{
		LastHandshake: time.Unix(sec, nsec),
		TxBytes:       txBytes,
		RxBytes:       rxBytes,
	}, nil
}

func findPeerInfo(ipcInput string, peerKey string, searchConfigKeys []string) (map[string]string, error) {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	hexKey := hex.EncodeToString(peerKeyParsed[:])

	lines := strings.Split(ipcInput, "\n")

	configFound := map[string]string{}
	foundPeer := false
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// If we're within the details of the found peer and encounter another public key,
		// this means we're starting another peer's details. So, stop.
		if strings.HasPrefix(line, "public_key=") && foundPeer {
			break
		}

		// Identify the peer with the specific public key
		if line == fmt.Sprintf("public_key=%s", hexKey) {
			foundPeer = true
		}

		for _, key := range searchConfigKeys {
			if foundPeer && strings.HasPrefix(line, key+"=") {
				v := strings.SplitN(line, "=", 2)
				configFound[v[0]] = v[1]
			}
		}
	}

	// todo: use multierr
	for _, key := range searchConfigKeys {
		if _, ok := configFound[key]; !ok {
			return configFound, fmt.Errorf("config key not found: %s", key)
		}
	}
	if !foundPeer {
		return nil, fmt.Errorf("peer not found: %s", peerKey)
	}

	return configFound, nil
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

func getFwmark() int {
	if runtime.GOOS == "linux" && !nbnet.CustomRoutingDisabled() {
		return nbnet.NetbirdFwmark
	}
	return 0
}
