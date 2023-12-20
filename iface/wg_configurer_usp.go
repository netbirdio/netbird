package iface

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgUSPConfigurer struct {
	device *device.Device
}

func newWGUSPConfigurer(device *device.Device) wgConfigurer {
	return &wgUSPConfigurer{
		device: device,
	}
}

func (c *wgUSPConfigurer) configureInterface(privateKey string, port int) error {
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

	output := ""
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
		if strings.HasPrefix(line, "private_key=") || strings.HasPrefix(line, "listen_port=") ||
			strings.HasPrefix(line, "public_key=") || strings.HasPrefix(line, "preshared_key=") ||
			strings.HasPrefix(line, "endpoint=") || strings.HasPrefix(line, "persistent_keepalive_interval=") ||
			strings.HasPrefix(line, "allowed_ip=") {
			output += line + "\n"
		}
	}

	if !removedAllowedIP {
		return fmt.Errorf("allowedIP not found")
	} else {
		return c.device.IpcSet(output)
	}
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
