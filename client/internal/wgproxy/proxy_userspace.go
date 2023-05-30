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
	var err error
	localConn, err := net.Dial("udp", fmt.Sprintf(":%d", p.localWGListenPort))
	if err != nil {
		log.Errorf("failed dialing to local Wireguard port %s", err)
		return nil, err
	}

	go p.proxyToRemote(localConn, turnConn)
	go p.proxyToLocal(localConn, turnConn)

	return localConn.LocalAddr(), nil
}

// Close resources
func (p *WGUserSpaceProxy) Close() error {
	p.cancel()
	return nil
}

// proxyToRemote proxies everything from Wireguard to the RemoteKey peer
// blocks
func (p *WGUserSpaceProxy) proxyToRemote(localConn, turnConn net.Conn) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			n, err := localConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = turnConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}

// proxyToLocal proxies everything from the RemoteKey peer to local Wireguard
// blocks
func (p *WGUserSpaceProxy) proxyToLocal(localConn, turnConn net.Conn) {
	defer func() {
		_ = localConn.Close()
	}()
	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			n, err := turnConn.Read(buf)
			if err != nil {
				continue
			}

			_, err = localConn.Write(buf[:n])
			if err != nil {
				continue
			}
		}
	}
}
