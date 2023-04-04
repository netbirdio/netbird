package proxy

import (
	log "github.com/sirupsen/logrus"
	"net"
)

// NoProxy is used just to configure WireGuard without any local proxy in between.
// Used when the WireGuard interface is userspace and uses bind.ICEBind
type NoProxy struct {
	config Config
}

// NewNoProxy creates a new NoProxy with a provided config
func NewNoProxy(config Config) *NoProxy {
	return &NoProxy{config: config}
}

// Close removes peer from the WireGuard interface
func (p *NoProxy) Close() error {
	err := p.config.WgInterface.RemovePeer(p.config.RemoteKey)
	if err != nil {
		return err
	}
	return nil
}

// Start just updates WireGuard peer with the remote address
func (p *NoProxy) Start(remoteConn net.Conn) error {

	log.Debugf("using NoProxy to connect to peer %s at %s", p.config.RemoteKey, remoteConn.RemoteAddr().String())
	addr, err := net.ResolveUDPAddr("udp", remoteConn.RemoteAddr().String())
	if err != nil {
		return err
	}
	return p.config.WgInterface.UpdatePeer(p.config.RemoteKey, p.config.AllowedIps, DefaultWgKeepAlive,
		addr, p.config.PreSharedKey)
}

func (p *NoProxy) Type() Type {
	return TypeNoProxy
}
