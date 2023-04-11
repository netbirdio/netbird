package proxy

import (
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/iface"
)

// DirectNoProxy is used when there is no need for a proxy between ICE and WireGuard.
// This is possible in either of these cases:
// - peers are in the same local network
// - one of the peers has a public static IP (host)
// DirectNoProxy will just update remote peer with a remote host and fixed WireGuard port (r.g. 51820).
// In order DirectNoProxy to work, WireGuard port has to be fixed for the time being.
type DirectNoProxy struct {
	wgInterface *iface.WGIface

	remoteKey  string
	allowedIps string

	// RemoteWgListenPort is a WireGuard port of a remote peer.
	// It is used instead of the hardcoded 51820 port.
	remoteWgListenPort int
}

// NewDirectNoProxy creates a new DirectNoProxy with a provided config and remote peer's WireGuard listen port
func NewDirectNoProxy(wgInterface *iface.WGIface, remoteKey string, allowedIps string, remoteWgPort int) *DirectNoProxy {
	return &DirectNoProxy{
		wgInterface:        wgInterface,
		remoteKey:          remoteKey,
		allowedIps:         allowedIps,
		remoteWgListenPort: remoteWgPort}
}

// Close removes peer from the WireGuard interface
func (p *DirectNoProxy) Close() error {
	err := p.wgInterface.RemovePeer(p.remoteKey)
	if err != nil {
		return err
	}
	return nil
}

// Start just updates WireGuard peer with the remote IP and default WireGuard port
func (p *DirectNoProxy) Start(remoteConn net.Conn) error {

	log.Debugf("using DirectNoProxy while connecting to peer %s", p.remoteKey)
	addr, err := net.ResolveUDPAddr("udp", remoteConn.RemoteAddr().String())
	if err != nil {
		return err
	}
	addr.Port = p.remoteWgListenPort
	err = p.wgInterface.UpdatePeer(p.remoteKey, p.allowedIps, addr)

	if err != nil {
		return err
	}

	return nil
}

// Type returns the type of this proxy
func (p *DirectNoProxy) Type() Type {
	return TypeDirectNoProxy
}
