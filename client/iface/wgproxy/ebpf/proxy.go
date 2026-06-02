//go:build linux && !android

package ebpf

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/bufsize"
	"github.com/netbirdio/netbird/client/iface/wgproxy/rawsocket"
	"github.com/netbirdio/netbird/client/internal/ebpf"
	ebpfMgr "github.com/netbirdio/netbird/client/internal/ebpf/manager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

const (
	loopbackAddr = "127.0.0.1"
)

// WGEBPFProxy definition for proxy with EBPF support
type WGEBPFProxy struct {
	localWGListenPort int
	proxyPort         int
	mtu               uint16

	ebpfManager   ebpfMgr.Manager
	turnConnStore map[uint16]net.Conn
	turnConnMutex sync.Mutex

	lastUsedPort uint16
	rawConnIPv4  net.PacketConn
	rawConnIPv6  net.PacketConn
	conn         transport.UDPConn

	ctx       context.Context
	ctxCancel context.CancelFunc
}

// NewWGEBPFProxy create new WGEBPFProxy instance
func NewWGEBPFProxy(wgPort int, mtu uint16) *WGEBPFProxy {
	log.Debugf("instantiate ebpf proxy")
	wgProxy := &WGEBPFProxy{
		localWGListenPort: wgPort,
		mtu:               mtu,
		ebpfManager:       ebpf.GetEbpfManagerInstance(),
		turnConnStore:     make(map[uint16]net.Conn),
	}
	return wgProxy
}

// Listen load ebpf program and listen the proxy
func (p *WGEBPFProxy) Listen() error {
	pl := portLookup{}
	proxyPort, err := pl.searchFreePort()
	if err != nil {
		return err
	}
	p.proxyPort = proxyPort

	// Prepare IPv4 raw socket (required)
	p.rawConnIPv4, err = rawsocket.PrepareSenderRawSocketIPv4()
	if err != nil {
		return err
	}

	// Prepare IPv6 raw socket (optional)
	p.rawConnIPv6, err = rawsocket.PrepareSenderRawSocketIPv6()
	if err != nil {
		log.Warnf("failed to prepare IPv6 raw socket, continuing with IPv4 only: %v", err)
	}

	err = p.ebpfManager.LoadWgProxy(proxyPort, p.localWGListenPort)
	if err != nil {
		if closeErr := p.rawConnIPv4.Close(); closeErr != nil {
			log.Warnf("failed to close IPv4 raw socket: %v", closeErr)
		}
		if p.rawConnIPv6 != nil {
			if closeErr := p.rawConnIPv6.Close(); closeErr != nil {
				log.Warnf("failed to close IPv6 raw socket: %v", closeErr)
			}
		}
		return err
	}

	addr := net.UDPAddr{
		Port: proxyPort,
		IP:   net.ParseIP(loopbackAddr),
	}

	p.ctx, p.ctxCancel = context.WithCancel(context.Background())

	conn, err := nbnet.ListenUDP("udp", &addr)
	if err != nil {
		if cErr := p.Free(); cErr != nil {
			log.Errorf("Failed to close the wgproxy: %s", cErr)
		}
		return err
	}
	p.conn = conn

	go p.proxyToRemote()
	log.Infof("local wg proxy listening on: %d", proxyPort)
	return nil
}

// AddTurnConn add new turn connection for the proxy
func (p *WGEBPFProxy) AddTurnConn(turnConn net.Conn) (*net.UDPAddr, error) {
	wgEndpointPort, err := p.storeTurnConn(turnConn)
	if err != nil {
		return nil, err
	}

	log.Infof("turn conn added to wg proxy store: %s, endpoint port: :%d", turnConn.RemoteAddr(), wgEndpointPort)

	wgEndpoint := &net.UDPAddr{
		IP:   net.ParseIP(loopbackAddr),
		Port: int(wgEndpointPort),
	}
	return wgEndpoint, nil
}

// Free resources except the remoteConns will be keep open.
func (p *WGEBPFProxy) Free() error {
	log.Debugf("free up ebpf wg proxy")
	if p.ctx != nil && p.ctx.Err() != nil {
		//nolint
		return nil
	}

	p.ctxCancel()

	var result *multierror.Error
	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if err := p.ebpfManager.FreeWGProxy(); err != nil {
		result = multierror.Append(result, err)
	}

	if p.rawConnIPv4 != nil {
		if err := p.rawConnIPv4.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if p.rawConnIPv6 != nil {
		if err := p.rawConnIPv6.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return nberrors.FormatErrorOrNil(result)
}

// GetProxyPort returns the proxy listening port.
func (p *WGEBPFProxy) GetProxyPort() uint16 {
	return uint16(p.proxyPort)
}

// proxyToRemote read messages from local WireGuard interface and forward it to remote conn
// From this go routine has only one instance.
func (p *WGEBPFProxy) proxyToRemote() {
	buf := make([]byte, p.mtu+bufsize.WGBufferOverhead)
	for p.ctx.Err() == nil {
		if err := p.readAndForwardPacket(buf); err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Errorf("failed to proxy packet to remote conn: %s", err)
		}
	}
}

func (p *WGEBPFProxy) readAndForwardPacket(buf []byte) error {
	n, addr, err := p.conn.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("failed to read UDP packet from WG: %w", err)
	}

	p.turnConnMutex.Lock()
	conn, ok := p.turnConnStore[uint16(addr.Port)]
	p.turnConnMutex.Unlock()
	if !ok {
		if p.ctx.Err() == nil {
			log.Debugf("turn conn not found by port because conn already has been closed: %d", addr.Port)
		}
		return nil
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		return fmt.Errorf("failed to forward local WG packet (%d) to remote turn conn: %w", addr.Port, err)
	}
	return nil
}

func (p *WGEBPFProxy) storeTurnConn(turnConn net.Conn) (uint16, error) {
	p.turnConnMutex.Lock()
	defer p.turnConnMutex.Unlock()

	np, err := p.nextFreePort()
	if err != nil {
		return np, err
	}
	p.turnConnStore[np] = turnConn
	return np, nil
}

func (p *WGEBPFProxy) removeTurnConn(turnConnID uint16) {
	p.turnConnMutex.Lock()
	defer p.turnConnMutex.Unlock()

	_, ok := p.turnConnStore[turnConnID]
	if ok {
		log.Debugf("remove turn conn from store by port: %d", turnConnID)
	}
	delete(p.turnConnStore, turnConnID)
}

func (p *WGEBPFProxy) nextFreePort() (uint16, error) {
	if len(p.turnConnStore) == 65535 {
		return 0, fmt.Errorf("reached maximum turn connection numbers")
	}
generatePort:
	if p.lastUsedPort == 65535 {
		p.lastUsedPort = 1
	} else {
		p.lastUsedPort++
	}

	if _, ok := p.turnConnStore[p.lastUsedPort]; ok {
		goto generatePort
	}
	return p.lastUsedPort, nil
}
