package iface

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

type MockWGIface struct {
	CreateFunc                 func() error
	CreateOnAndroidFunc        func(routeRange []string, ip string, domains []string) error
	IsUserspaceBindFunc        func() bool
	NameFunc                   func() string
	AddressFunc                func() device.WGAddress
	ToInterfaceFunc            func() *net.Interface
	UpFunc                     func() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddrFunc             func(newAddr string) error
	UpdatePeerFunc             func(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeerFunc             func(peerKey string) error
	AddAllowedIPFunc           func(peerKey string, allowedIP string) error
	RemoveAllowedIPFunc        func(peerKey string, allowedIP string) error
	CloseFunc                  func() error
	SetFilterFunc              func(filter device.PacketFilter) error
	GetFilterFunc              func() device.PacketFilter
	GetDeviceFunc              func() *device.FilteredDevice
	GetStatsFunc               func(peerKey string) (configurer.WGStats, error)
	GetInterfaceGUIDStringFunc func() (string, error)
	GetProxyFunc               func() wgproxy.Proxy
}

func (m *MockWGIface) GetInterfaceGUIDString() (string, error) {
	return m.GetInterfaceGUIDStringFunc()
}

func (m *MockWGIface) Create() error {
	return m.CreateFunc()
}

func (m *MockWGIface) CreateOnAndroid(routeRange []string, ip string, domains []string) error {
	return m.CreateOnAndroidFunc(routeRange, ip, domains)
}

func (m *MockWGIface) IsUserspaceBind() bool {
	return m.IsUserspaceBindFunc()
}

func (m *MockWGIface) Name() string {
	return m.NameFunc()
}

func (m *MockWGIface) Address() device.WGAddress {
	return m.AddressFunc()
}

func (m *MockWGIface) ToInterface() *net.Interface {
	return m.ToInterfaceFunc()
}

func (m *MockWGIface) Up() (*bind.UniversalUDPMuxDefault, error) {
	return m.UpFunc()
}

func (m *MockWGIface) UpdateAddr(newAddr string) error {
	return m.UpdateAddrFunc(newAddr)
}

func (m *MockWGIface) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	return m.UpdatePeerFunc(peerKey, allowedIps, keepAlive, endpoint, preSharedKey)
}

func (m *MockWGIface) RemovePeer(peerKey string) error {
	return m.RemovePeerFunc(peerKey)
}

func (m *MockWGIface) AddAllowedIP(peerKey string, allowedIP string) error {
	return m.AddAllowedIPFunc(peerKey, allowedIP)
}

func (m *MockWGIface) RemoveAllowedIP(peerKey string, allowedIP string) error {
	return m.RemoveAllowedIPFunc(peerKey, allowedIP)
}

func (m *MockWGIface) Close() error {
	return m.CloseFunc()
}

func (m *MockWGIface) SetFilter(filter device.PacketFilter) error {
	return m.SetFilterFunc(filter)
}

func (m *MockWGIface) GetFilter() device.PacketFilter {
	return m.GetFilterFunc()
}

func (m *MockWGIface) GetDevice() *device.FilteredDevice {
	return m.GetDeviceFunc()
}

func (m *MockWGIface) GetStats(peerKey string) (configurer.WGStats, error) {
	return m.GetStatsFunc(peerKey)
}

func (m *MockWGIface) GetProxy() wgproxy.Proxy {
	//TODO implement me
	panic("implement me")
}
