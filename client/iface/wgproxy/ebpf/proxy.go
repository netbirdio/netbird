//go:build linux && !android

package ebpf

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

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
	// batchConnIPv4/IPv6 wrap the raw sockets so the inject path can write a
	// whole batch of packets with one sendmmsg (WriteBatch) instead of one
	// WriteTo per packet. Non-nil whenever the matching raw socket is present.
	batchConnIPv4 *ipv4.PacketConn
	batchConnIPv6 *ipv6.PacketConn
	conn          transport.UDPConn

	// batchRead drains several relayed packets from the local WireGuard socket
	// with one recvmmsg and forwards them back-to-back, cutting the per-packet
	// syscall and wakeup overhead on the hot send path. Gated by
	// NB_RELAY_BATCH_READ; the per-packet path stays the default.
	batchRead bool

	ctx       context.Context
	ctxCancel context.CancelFunc
}

// batchReadSize bounds how many packets are drained from the local WireGuard
// socket per recvmmsg when NB_RELAY_BATCH_READ is set.
const batchReadSize = 64

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

	p.batchConnIPv4 = ipv4.NewPacketConn(p.rawConnIPv4)

	// Prepare IPv6 raw socket (optional)
	p.rawConnIPv6, err = rawsocket.PrepareSenderRawSocketIPv6()
	if err != nil {
		log.Warnf("failed to prepare IPv6 raw socket, continuing with IPv4 only: %v", err)
	}
	if p.rawConnIPv6 != nil {
		p.batchConnIPv6 = ipv6.NewPacketConn(p.rawConnIPv6)
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
	nbnet.SizeRelaySocketBuffers(conn)
	p.batchRead = os.Getenv("NB_RELAY_BATCH_READ") == "true"

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
	if p.batchRead {
		if pc, ok := p.conn.(net.PacketConn); ok {
			p.proxyToRemoteBatch(pc)
			return
		}
		log.Warnf("batch read requested but proxy conn %T is not a net.PacketConn; using per-packet read", p.conn)
	}

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

// proxyToRemoteBatch drains up to batchReadSize packets from the local
// WireGuard socket with one recvmmsg and forwards each through the same
// per-packet, per-source-port turn lookup as the single-packet path. Because
// the single proxy socket is shared by every relayed peer, recvmmsg yields each
// packet's source address, which selects the destination turn conn. Draining
// several packets per recvmmsg amortizes the read syscall and wakeup across the
// batch on the hot send path.
func (p *WGEBPFProxy) proxyToRemoteBatch(pc net.PacketConn) {
	batchConn := ipv4.NewPacketConn(pc)
	bufSize := int(p.mtu) + bufsize.WGBufferOverhead
	msgs := make([]ipv4.Message, batchReadSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, bufSize)}
	}

	for p.ctx.Err() == nil {
		n, err := batchConn.ReadBatch(msgs, 0)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Errorf("failed to batch read UDP packets from WG: %s", err)
			continue
		}

		for i := 0; i < n; i++ {
			p.forwardBatchPacket(msgs[i].Buffers[0][:msgs[i].N], msgs[i].Addr)
		}
	}
}

// forwardBatchPacket forwards one packet read in a batch to the turn conn that
// owns its source port, mirroring readAndForwardPacket for the single-read path.
func (p *WGEBPFProxy) forwardBatchPacket(payload []byte, addr net.Addr) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		log.Errorf("unexpected batch read source address type %T", addr)
		return
	}

	p.turnConnMutex.Lock()
	conn, ok := p.turnConnStore[uint16(udpAddr.Port)]
	p.turnConnMutex.Unlock()
	if !ok {
		if p.ctx.Err() == nil {
			log.Debugf("turn conn not found by port because conn already has been closed: %d", udpAddr.Port)
		}
		return
	}

	if _, err := conn.Write(payload); err != nil {
		log.Errorf("failed to forward local WG packet (%d) to remote turn conn: %s", udpAddr.Port, err)
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
