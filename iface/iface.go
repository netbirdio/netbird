package iface

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
)

const (
	DefaultMTU    = 1280
	DefaultWgPort = 51820
)

// WGIface represents a interface instance
type WGIface struct {
	Name      string
	Port      int
	MTU       int
	Address   WGAddress
	Interface NetInterface
	mu        sync.Mutex
	Bind      *UserBind
}

// WGAddress Wireguard parsed address
type WGAddress struct {
	IP      net.IP
	Network *net.IPNet
}

func (addr *WGAddress) String() string {
	maskSize, _ := addr.Network.Mask.Size()
	return fmt.Sprintf("%s/%d", addr.IP.String(), maskSize)
}

// NetInterface represents a generic network tunnel interface
type NetInterface interface {
	Close() error
}

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(iface string, address string, mtu int) (*WGIface, error) {
	wgIface := &WGIface{
		Name: iface,
		MTU:  mtu,
		mu:   sync.Mutex{},
	}

	wgAddress, err := parseAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgIface.Address = wgAddress

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

// Close closes the tunnel interface
func (w *WGIface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	err := w.Interface.Close()
	if err != nil {
		return err
	}

	if runtime.GOOS == "darwin" {
		sockPath := "/var/run/wireguard/" + w.Name + ".sock"
		if _, statErr := os.Stat(sockPath); statErr == nil {
			statErr = os.Remove(sockPath)
			if statErr != nil {
				return statErr
			}
		}
	}

	return nil
}
