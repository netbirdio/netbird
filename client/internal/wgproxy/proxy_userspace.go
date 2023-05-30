package wgproxy

import (
	"context"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// WGUserSpaceProxy proxies
type WGUserSpaceProxy struct {
	localWGListenPort int
	ctx               context.Context
	cancel            context.CancelFunc

	remoteConn net.Conn
	localConn  net.Conn
}

// NewUSProxy instantiate new user space proxy
func NewUSProxy(wgPort int) *WGUserSpaceProxy {
	log.Debugf("instantiate user space proxy")
	p := &WGUserSpaceProxy{
		localWGListenPort: wgPort,
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

// AddTurnConn add new turn connection for the proxy
func (p *WGUserSpaceProxy) AddTurnConn(turnConn net.Conn) (net.Addr, error) {
	p.remoteConn = turnConn

	var err error
	p.localConn, err = net.Dial("udp", fmt.Sprintf(":%d", p.localWGListenPort))
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		return nil, err
	}

	go p.proxyToRemote()
	go p.proxyToLocal()

	return p.localConn.LocalAddr(), nil
}

// Close resources
func (p *WGUserSpaceProxy) Close() error {
	p.cancel()
	if c := p.localConn; c != nil {
		err := p.localConn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// proxyToRemote proxies everything from Wireguard to the RemoteKey peer
// blocks
func (p *WGUserSpaceProxy) proxyToRemote() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			n, err := p.localConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = p.remoteConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}

// proxyToLocal proxies everything from the RemoteKey peer to local Wireguard
// blocks
func (p *WGUserSpaceProxy) proxyToLocal() {

	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			n, err := p.remoteConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = p.localConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}
