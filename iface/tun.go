package iface

import "github.com/netbirdio/netbird/iface/bind"

type MobileIFaceArguments struct {
	Routes        []string
	Dns           string
	SearchDomains []string
}

type wgTunDevice interface {
	Create() (wgConfigurer, error)
	UpdateAddr(address WGAddress) error
	WgAddress() WGAddress
	DeviceName() string
	Close() error
	IceBind() *bind.ICEBind  // todo eliminate this function
	Wrapper() *DeviceWrapper // todo eliminate this function
}
