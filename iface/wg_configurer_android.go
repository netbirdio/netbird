package iface

import (
	"errors"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	errFuncNotImplemented = errors.New("function not implemented")
)

type wGConfigurer struct {
	deviceName string
	address    WGAddress
	mtu        int
	wgAdapter  WGAdapter
}

func newWGConfigurer(deviceName string, address WGAddress, mtu int, wgAdapter WGAdapter) wGConfigurer {
	return wGConfigurer{
		deviceName: deviceName,
		address:    address,
		mtu:        mtu,
		wgAdapter:  wgAdapter,
	}
}

func (c *wGConfigurer) configureInterface(privateKey string, port int) error {
	c.wgAdapter.ConfigureInterface(c.address.String(), privateKey, port)
	return nil
}

func (c *wGConfigurer) updateAddress(address WGAddress) error {
	c.address = address
	c.wgAdapter.UpdateAddr(address.String())
	return nil
}

func (c *wGConfigurer) updatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	c.wgAdapter.AddPeer(peerKey, allowedIps, "", endpoint.String())
	return nil
}

func (c *wGConfigurer) removePeer(peerKey string) error {
	c.wgAdapter.RemovePeer(peerKey)
	return nil
}

func (c *wGConfigurer) addAllowedIP(peerKey string, allowedIP string) error {
	return errFuncNotImplemented
}

func (c *wGConfigurer) removeAllowedIP(peerKey string, allowedIP string) error {
	return errFuncNotImplemented
}

func (c *wGConfigurer) close() {
	// todo: implement
}
