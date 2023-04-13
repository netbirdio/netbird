package proxy

import (
	log "github.com/sirupsen/logrus"
	"net"
)

// DirectNoProxy is used when there is no need for a proxy between ICE and WireGuard.
// This is possible in either of these cases:
// - peers are in the same local network
// - one of the peers has a public static IP (host)
// DirectNoProxy will just update remote peer with a remote host and fixed WireGuard port (r.g. 51820).
// In order DirectNoProxy to work, WireGuard port has to be fixed for the time being.
type DirectNoProxy struct {
	config Config
	// RemoteWgListenPort is a WireGuard port of a remote peer.
	// It is used instead of the hardcoded 51820 port.
	RemoteWgListenPort int
}

// NewDirectNoProxy creates a new DirectNoProxy with a provided config and remote peer's WireGuard listen port
func NewDirectNoProxy(config Config, remoteWgPort int) *DirectNoProxy {
	return &DirectNoProxy{config: config, RemoteWgListenPort: remoteWgPort}
}

// Close removes peer from the WireGuard interface
func (p *DirectNoProxy) Close() error {
	err := p.config.WgInterface.RemovePeer(p.config.RemoteKey)
	if err != nil {
		return err
	}
	return nil
}

// Start just updates WireGuard peer with the remote IP and default WireGuard port
func (p *DirectNoProxy) Start(remoteConn net.Conn) error {

	log.Debugf("using DirectNoProxy while connecting to peer %s", p.config.RemoteKey)
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

// Type returns the type of this proxy
func (p *DirectNoProxy) Type() Type {
	return TypeDirectNoProxy
}
