//go:build ios || android
// +build ios android

package iface

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	errFuncNotImplemented = errors.New("function not implemented")
)

type wGConfigurer struct {
	tunDevice *tunDevice
}

func newWGConfigurer(tunDevice *tunDevice) wGConfigurer {
	return wGConfigurer{
		tunDevice: tunDevice,
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

	return c.tunDevice.Device().IpcSet(toWgUserspaceString(config))
}

func (c *wGConfigurer) updatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
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

	return c.tunDevice.Device().IpcSet(toWgUserspaceString(config))
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
	return c.tunDevice.Device().IpcSet(toWgUserspaceString(config))
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

	return c.tunDevice.Device().IpcSet(toWgUserspaceString(config))
}

func (c *wGConfigurer) removeAllowedIP(peerKey string, ip string) error {
	ipc, err := c.tunDevice.Device().IpcGet()
	if err != nil {
		return err
	}

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
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
		return c.tunDevice.Device().IpcSet(output)
	}
}
