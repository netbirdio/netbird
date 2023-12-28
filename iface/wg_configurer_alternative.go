package iface

import (
	"encoding/hex"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgAlternativeConfigurer struct {
	device     *device.Device
	deviceName string

	uapiListener net.Listener
}

func newWgAlternativeConfigurer(device *device.Device, deviceName string) wgConfigurer {
	wgCfg := &wgAlternativeConfigurer{
		device:     device,
		deviceName: deviceName,
	}
	wgCfg.startUAPI()
	return wgCfg
}

func (c *wgAlternativeConfigurer) configureInterface(privateKey string, port int) error {
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

	return c.configure(config)
}

func (c *wgAlternativeConfigurer) updatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
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

	return c.configure(config)
}

func (c *wgAlternativeConfigurer) removePeer(peerKey string) error {
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
	return c.configure(config)
}

func (c *wgAlternativeConfigurer) addAllowedIP(peerKey string, allowedIP string) error {
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

	return c.configure(config)
}

func (c *wgAlternativeConfigurer) removeAllowedIP(peerKey string, ip string) error {
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

// startUAPI starts the UAPI listener for managing the WireGuard interface via external tool
func (t *wgAlternativeConfigurer) startUAPI() {
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
				log.Traceln("uapi Accept failed with error: ", uapiErr)
				return
			}
			go func() {
				t.device.IpcHandle(uapiConn)
			}()
		}
	}(t.uapiListener)
}

func (t *wgAlternativeConfigurer) close() {
	if t.uapiListener != nil {
		err := t.uapiListener.Close()
		if err != nil {
			log.Errorf("failed to close uapi listener: %v", err)
		}
	}
}

func (t *wgAlternativeConfigurer) configure(config wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	// validate if device with name exists
	_, err = wg.Device(t.deviceName)
	if err != nil {
		return err
	}
	log.Tracef("got Wireguard device %s", t.deviceName)

	return wg.ConfigureDevice(t.deviceName, config)
}
