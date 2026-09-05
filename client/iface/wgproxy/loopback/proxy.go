//go:build linux && !android

package loopback

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/bufsize"
	"github.com/netbirdio/netbird/client/iface/wgproxy/rawsocket"
)

const (
	loopbackDevice = "lo"

	portRangeStart = 3128
	portRangeEnd   = portRangeStart + 100
)

// Proxy forwards packets between relayed connections and a local kernel
// WireGuard instance. Every relayed peer gets its own loopback address as its
// WireGuard endpoint, so a single socket serves all of them: the destination
// address of an incoming packet identifies the peer.
type Proxy struct {
	localWGListenPort int
	mtu               uint16
	proxyPort         int

	conn        *net.UDPConn
	packetConn  *ipv4.PacketConn
	loIndex     int
	rawConnIPv4 net.PacketConn
	rawConnIPv6 net.PacketConn

	relayedConnMutex sync.Mutex
	relayedConnStore map[netip.Addr]net.Conn
	addrs            allocator

	ctx       context.Context
	ctxCancel context.CancelFunc
}

// NewProxy creates a proxy for the WireGuard instance listening on wgPort.
func NewProxy(wgPort int, mtu uint16) *Proxy {
	log.Debugf("instantiate loopback wg proxy")
	return &Proxy{
		localWGListenPort: wgPort,
		mtu:               mtu,
		relayedConnStore:  make(map[netip.Addr]net.Conn),
	}
}

// Listen opens the shared socket and starts forwarding WireGuard packets to the
// relayed connections.
func (p *Proxy) Listen() error {
	rawConnIPv4, err := rawsocket.PrepareSenderRawSocketIPv4()
	if err != nil {
		return fmt.Errorf("prepare IPv4 raw socket: %w", err)
	}
	p.rawConnIPv4 = rawConnIPv4

	p.rawConnIPv6, err = rawsocket.PrepareSenderRawSocketIPv6()
	if err != nil {
		log.Warnf("failed to prepare IPv6 raw socket, continuing with IPv4 only: %v", err)
	}

	loopback, err := net.InterfaceByName(loopbackDevice)
	if err != nil {
		if freeErr := p.Free(); freeErr != nil {
			log.Errorf("failed to free the wgproxy: %s", freeErr)
		}
		return fmt.Errorf("look up %s: %w", loopbackDevice, err)
	}
	p.loIndex = loopback.Index

	if err := p.listen(); err != nil {
		if freeErr := p.Free(); freeErr != nil {
			log.Errorf("failed to free the wgproxy: %s", freeErr)
		}
		return err
	}

	p.ctx, p.ctxCancel = context.WithCancel(context.Background())

	go p.proxyToRemote()
	log.Infof("local wg proxy listening on %s:%d", addrRangePrefix, p.proxyPort)
	return nil
}

// listen binds the shared socket on the first free port of the range. The bind
// has to be a wildcard one to receive every peer address in the range, so it is
// restricted to the loopback device: without that the port would be reachable
// on every interface.
func (p *Proxy) listen() error {
	var lastErr error
	for port := portRangeStart; port <= portRangeEnd; port++ {
		err := p.listenOn(port)
		if err == nil {
			p.proxyPort = port
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("bind proxy port in range %d-%d: %w", portRangeStart, portRangeEnd, lastErr)
}

func (p *Proxy) listenOn(proxyPort int) error {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, loopbackDevice); err != nil {
					sockErr = fmt.Errorf("bind to %s: %w", loopbackDevice, err)
					return
				}
			}); err != nil {
				return fmt.Errorf("control socket: %w", err)
			}
			return sockErr
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", proxyPort))
	if err != nil {
		return fmt.Errorf("listen on :%d: %w", proxyPort, err)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		if closeErr := conn.Close(); closeErr != nil {
			log.Errorf("failed to close proxy conn: %s", closeErr)
		}
		return fmt.Errorf("unexpected conn type %T", conn)
	}

	packetConn := ipv4.NewPacketConn(udpConn)
	// the destination address carries the peer identity, the interface index is
	// checked on receive as a second line of defense behind SO_BINDTODEVICE
	if err := packetConn.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		if closeErr := udpConn.Close(); closeErr != nil {
			log.Errorf("failed to close proxy conn: %s", closeErr)
		}
		return fmt.Errorf("request destination address: %w", err)
	}

	p.conn = udpConn
	p.packetConn = packetConn
	return nil
}

// AddRelayedConn assigns an endpoint address to the relayed connection and
// returns the address WireGuard should send to, along with the key the
// connection is stored under.
func (p *Proxy) AddRelayedConn(relayedConn net.Conn) (*net.UDPAddr, netip.Addr, error) {
	addr, err := p.storeRelayedConn(relayedConn)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	log.Infof("relayed conn added to wg proxy store: %s, endpoint address: %s", relayedConn.RemoteAddr(), addr)

	return &net.UDPAddr{
		IP:   addr.AsSlice(),
		Port: p.proxyPort,
	}, addr, nil
}

// Free releases the proxy resources. The relayed connections are left open.
func (p *Proxy) Free() error {
	log.Debugf("free up loopback wg proxy")
	if p.ctx != nil && p.ctx.Err() != nil {
		//nolint
		return nil
	}

	if p.ctxCancel != nil {
		p.ctxCancel()
	}

	var result *multierror.Error
	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			result = multierror.Append(result, err)
		}
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

// proxyToRemote reads packets from the local WireGuard instance and forwards
// them to the relayed connection the destination address belongs to.
func (p *Proxy) proxyToRemote() {
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

func (p *Proxy) readAndForwardPacket(buf []byte) error {
	n, cm, _, err := p.packetConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("read UDP packet from WG: %w", err)
	}

	if cm == nil {
		return fmt.Errorf("no control message on packet")
	}

	if cm.IfIndex != p.loIndex {
		log.Tracef("dropping packet received on interface %d instead of %s", cm.IfIndex, loopbackDevice)
		return nil
	}

	dst, ok := netip.AddrFromSlice(cm.Dst.To4())
	if !ok || !inRange(dst) {
		log.Tracef("dropping packet for unexpected destination %s", cm.Dst)
		return nil
	}

	p.relayedConnMutex.Lock()
	conn, ok := p.relayedConnStore[dst]
	p.relayedConnMutex.Unlock()
	if !ok {
		if p.ctx.Err() == nil {
			log.Debugf("relayed conn not found by address because conn already has been closed: %s", dst)
		}
		return nil
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		return fmt.Errorf("forward local WG packet (%s) to remote relayed conn: %w", dst, err)
	}
	return nil
}

func (p *Proxy) storeRelayedConn(relayedConn net.Conn) (netip.Addr, error) {
	p.relayedConnMutex.Lock()
	defer p.relayedConnMutex.Unlock()

	addr, err := p.addrs.next(func(a netip.Addr) bool {
		_, ok := p.relayedConnStore[a]
		return ok
	})
	if err != nil {
		return netip.Addr{}, err
	}

	p.relayedConnStore[addr] = relayedConn
	return addr, nil
}

// removeRelayedConn releases an endpoint address. It only removes the entry
// while it still belongs to relayedConn, so a late release cannot take an
// address away from the peer it was handed to next.
func (p *Proxy) removeRelayedConn(addr netip.Addr, relayedConn net.Conn) {
	p.relayedConnMutex.Lock()
	defer p.relayedConnMutex.Unlock()

	if stored, ok := p.relayedConnStore[addr]; !ok || stored != relayedConn {
		return
	}

	log.Debugf("remove relayed conn from store by address: %s", addr)
	delete(p.relayedConnStore, addr)
}
