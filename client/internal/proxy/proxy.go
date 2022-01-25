package proxy

import (
	"github.com/wiretrustee/wiretrustee/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"io"
	"net"
	"time"
)

const DefaultWgKeepAlive = 25 * time.Second

type Config struct {
	WgListenAddr string
	RemoteKey    string
	WgInterface  iface.WGIface
	AllowedIps   string
	PreSharedKey *wgtypes.Key
}

type Proxy interface {
	io.Closer
	// Start creates a local remoteConn and starts proxying data from/to remoteConn
	Start(remoteConn net.Conn) error
}

type Mock struct {
	StartFunc func(remoteConn net.Conn) error
	CloseFunc func() error
}

func (p *Mock) Close() error {
	if p.CloseFunc == nil {
		return nil
	}
	return p.CloseFunc()
}

func (p *Mock) Start(remoteConn net.Conn) error {
	if p.StartFunc == nil {
		return nil
	}
	return p.StartFunc(remoteConn)
}

type Provider interface {
	CreateProxy(config Config) Proxy
}

type DefaultProvider struct{}

func (p *DefaultProvider) CreateProxy(config Config) Proxy {
	return NewWireguardProxy(config)
}

type ProviderMock struct {
	Proxy Proxy
}

func (p *ProviderMock) CreateProxy(config Config) Proxy {
	return p.Proxy
}
