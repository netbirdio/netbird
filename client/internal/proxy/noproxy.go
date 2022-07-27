package proxy

import (
	"github.com/netbirdio/netbird/iface"
	log "github.com/sirupsen/logrus"
	"net"
)

// NoProxy is used when there is no need for a proxy between ICE and Wireguard.
// This is possible in either of these cases:
// - peers are in the same local network
// - one of the peers has a public static IP (host)
// NoProxy will just update remote peer with a remote host and fixed Wireguard port (r.g. 51820).
// In order NoProxy to work, Wireguard port has to be fixed for the time being.
type NoProxy struct {
	config  Config
	relayed bool
}

func NewNoProxy(config Config, relayed bool) *NoProxy {
	return &NoProxy{
		config:  config,
		relayed: relayed,
	}
}

func (p *NoProxy) Close() error {
	err := p.config.WgInterface.RemovePeer(p.config.RemoteKey)
	if err != nil {
		return err
	}
	return nil
}

// Start just updates Wireguard peer with the remote IP and default Wireguard port
func (p *NoProxy) Start(remoteConn net.Conn) error {

	log.Debugf("using NoProxy while connecting to peer %s", p.config.RemoteKey)
	addr, err := net.ResolveUDPAddr("udp", remoteConn.RemoteAddr().String())
	if err != nil {
		return err
	}
	if !p.relayed {
		addr.Port = iface.DefaultWgPort
	}
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
