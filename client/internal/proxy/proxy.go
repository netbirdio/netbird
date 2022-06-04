package proxy

import (
	"github.com/netbirdio/netbird/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"io"
	"net"
	"time"
)

const DefaultWgKeepAlive = 25 * time.Second

type Type string

const (
	TypeNoProxy   Type = "NoProxy"
	TypeWireguard Type = "Wireguard"
	TypeDummy     Type = "Dummy"
)

type Config struct {
	WgListenAddr string
	RemoteKey    string
	WgInterface  *iface.WGIface
	AllowedIps   string
	PreSharedKey *wgtypes.Key
}

type Proxy interface {
	io.Closer
	// Start creates a local remoteConn and starts proxying data from/to remoteConn
	Start(remoteConn net.Conn) error
	Type() Type
}
