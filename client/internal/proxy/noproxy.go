package proxy

import (
	log "github.com/sirupsen/logrus"
	"net"
)

// NoProxy is used when there is no need for a proxy between ICE and WireGuard.
// This is possible in either of these cases:
// - peers are in the same local network
// - one of the peers has a public static IP (host)
// NoProxy will just update remote peer with a remote host and fixed WireGuard port (r.g. 51820).
// In order NoProxy to work, WireGuard port has to be fixed for the time being.
type NoProxy struct {
	config Config
	// RemoteWgListenPort is a WireGuard port of a remote peer.
	// It is used instead of the hardcoded 51820 port.
	RemoteWgListenPort int
}

// NewNoProxy creates a new NoProxy with a provided config and remote peer's WireGuard listen port
func NewNoProxy(config Config, remoteWgPort int) *NoProxy {
	return &NoProxy{config: config, RemoteWgListenPort: remoteWgPort}
}

func (p *NoProxy) Close() error {
	err := p.config.WgInterface.RemovePeer(p.config.RemoteKey)
	if err != nil {
		return err
	}
	return nil
}

// Start just updates WireGuard peer with the remote IP and default WireGuard port
func (p *NoProxy) Start(remoteConn net.Conn) error {

	log.Debugf("using NoProxy while connecting to peer %s", p.config.RemoteKey)
	addr, err := net.ResolveUDPAddr("udp", remoteConn.RemoteAddr().String())
	if err != nil {
		return err
	}
	addr.Port = p.RemoteWgListenPort
	err = p.config.WgInterface.UpdatePeer(p.config.RemoteKey, p.config.AllowedIps, DefaultWgKeepAlive,
		addr, p.config.PreSharedKey)

	if err != nil {
		return err
	}

	return nil
}

func (p *NoProxy) Type() Type {
	return TypeNoProxy
}
