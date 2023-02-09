package iface

import (
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

	wgAddress, err := newWGAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgIface.Address = wgAddress

	return wgIface, nil
}
