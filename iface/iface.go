package iface

import (
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"time"
)

const (
	defaultMTU = 1280
)

// WGIface represents a interface instance
type WGIface struct {
	Name      string
	Port      int
	MTU       int
	Address   WGAddress
	Interface NetInterface
}

type WGAddress struct {
	IP      net.IP
	Network *net.IPNet
}

// NetInterface represents a generic network tunnel interface
type NetInterface interface {
	Close() error
}

// CreateWithUserspace Creates a new Wireguard interface, using wireguard-go userspace implementation
func CreateWithUserspace(iface string, address string) (WGIface, error) {
	wgAddress, err := parseAddress(address)
	if err != nil {
		return WGIface{}, err
	}

	wgIface := WGIface{
		Name:    iface,
		Address: wgAddress,
		MTU:     defaultMTU,
	}

	tunIface, err := tun.CreateTUN(iface, wgIface.MTU)
	if err != nil {
		return wgIface, err
	}

	wgIface.Interface = tunIface

	// We need to create a wireguard-go device and listen to configuration requests
	tunDevice := device.NewDevice(tunIface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	err = tunDevice.Up()
	if err != nil {
		return wgIface, err
	}
	uapi, err := getUAPI(iface)
	if err != nil {
		return wgIface, err
	}

	go func() {
		for {
			uapiConn, uapiErr := uapi.Accept()
			if uapiErr != nil {
				log.Traceln("uapi Accept failed with error: ", uapiErr)
				continue
			}
			go tunDevice.IpcHandle(uapiConn)
		}
	}()

	log.Debugln("UAPI listener started")

	err = wgIface.assignAddr()
	if err != nil {
		return wgIface, err
	}
	return wgIface, nil
}

// parseAddress parse a string ("1.2.3.4/24") address to WG Address
func parseAddress(address string) (WGAddress, error) {
	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		return WGAddress{}, err
	}
	return WGAddress{
		IP:      ip,
		Network: network,
	}, nil
}

// configure peer for the wireguard device
func configureDevice(iface string, config wgtypes.Config) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	_, err = wg.Device(iface)
	if err != nil {
		return err
	}
	log.Debugf("got Wireguard device %s", iface)

	return wg.ConfigureDevice(iface, config)
}

// Exists checks whether specified Wireguard device exists or not
func Exists(iface string) (*bool, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()

	devices, err := wg.Devices()
	if err != nil {
		return nil, err
	}

	var exists bool
	for _, d := range devices {
		if d.Name == iface {
			exists = true
			return &exists, nil
		}
	}
	exists = false
	return &exists, nil
}

// Configure configures a Wireguard interface
// The interface must exist before calling this method (e.g. call interface.Create() before)
func Configure(iface string, privateKey string, port int) error {

	log.Debugf("configuring Wireguard interface %s", iface)

	log.Debugf("adding Wireguard private key")
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return err
	}
	fwmark := 0
	config := wgtypes.Config{
		PrivateKey:   &key,
		ReplacePeers: false,
		FirewallMark: &fwmark,
		ListenPort:   &port,
	}

	return configureDevice(iface, config)
}

// GetListenPort returns the listening port of the Wireguard endpoint
func GetListenPort(iface string) (*int, error) {
	log.Debugf("getting Wireguard listen port of interface %s", iface)

	//discover Wireguard current configuration
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()

	d, err := wg.Device(iface)
	if err != nil {
		return nil, err
	}
	log.Debugf("got Wireguard device listen port %s, %d", iface, d.ListenPort)

	return &d.ListenPort, nil
}

// UpdatePeer updates existing Wireguard Peer or creates a new one if doesn't exist
// Endpoint is optional
func UpdatePeer(iface string, peerKey string, allowedIps string, keepAlive time.Duration, endpoint string, preSharedKey *wgtypes.Key) error {

	log.Debugf("updating interface %s peer %s: endpoint %s ", iface, peerKey, endpoint)

	//parse allowed ips
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
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	err = configureDevice(iface, config)
	if err != nil {
		return err
	}

	if endpoint != "" {
		return UpdatePeerEndpoint(iface, peerKey, endpoint)
	}

	return nil
}

// UpdatePeerEndpoint updates a Wireguard interface Peer with the new endpoint
// Used when NAT hole punching was successful and an update of the remote peer endpoint is required
func UpdatePeerEndpoint(iface string, peerKey string, newEndpoint string) error {

	log.Debugf("updating peer %s endpoint %s ", peerKey, newEndpoint)

	peerAddr, err := net.ResolveUDPAddr("udp4", newEndpoint)
	if err != nil {
		return err
	}

	log.Debugf("parsed peer endpoint [%s]", peerAddr.String())

	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return err
	}

	peer := wgtypes.PeerConfig{
		PublicKey:         peerKeyParsed,
		ReplaceAllowedIPs: false,
		UpdateOnly:        true,
		Endpoint:          peerAddr,
	}
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}
	return configureDevice(iface, config)
}

// RemovePeer removes a Wireguard Peer from the interface iface
func RemovePeer(iface string, peerKey string) error {
	log.Debugf("Removing peer %s from interface %s ", peerKey, iface)

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

	return configureDevice(iface, config)
}

// CloseWithUserspace closes the User Space tunnel interface
func CloseWithUserspace(tunIface NetInterface) error {
	return tunIface.Close()
}
