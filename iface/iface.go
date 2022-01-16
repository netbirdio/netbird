package iface

import (
	"golang.zx2c4.com/wireguard/wgctrl"
	"net"
)

const (
	DefaultMTU = 1280
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

// NewWGIface Creates a new Wireguard interface instance
func NewWGIface(iface string, address string, mtu int) (WGIface, error) {
	wgIface := WGIface{
		Name: iface,
		MTU:  mtu,
	}

	wgAddress, err := parseAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgIface.Address = wgAddress

	return wgIface, nil
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

// CloseWithUserspace closes the User Space tunnel interface
func CloseWithUserspace(tunIface NetInterface) error {
	return tunIface.Close()
}
