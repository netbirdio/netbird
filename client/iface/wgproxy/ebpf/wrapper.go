//go:build linux && !android

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/bufsize"
	"github.com/netbirdio/netbird/client/iface/wgproxy/listener"
)

var (
	errIPv6ConnNotAvailable = errors.New("IPv6 endpoint but rawConnIPv6 is not available")
	errIPv4ConnNotAvailable = errors.New("IPv4 endpoint but rawConnIPv4 is not available")

	localHostNetIPv4 = net.ParseIP("127.0.0.1")
	localHostNetIPv6 = net.ParseIP("::1")

	serializeOpts = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
)

// PacketHeaders holds pre-created headers and buffers for efficient packet sending
type PacketHeaders struct {
	ipH           gopacket.SerializableLayer
	udpH          *layers.UDP
	layerBuffer   gopacket.SerializeBuffer
	localHostAddr net.IP
	isIPv4        bool
}

func NewPacketHeaders(localWGListenPort int, endpoint *net.UDPAddr) (*PacketHeaders, error) {
	var ipH gopacket.SerializableLayer
	var networkLayer gopacket.NetworkLayer
	var localHostAddr net.IP
	var isIPv4 bool

	// Check if source address is IPv4 or IPv6
	if endpoint.IP.To4() != nil {
		// IPv4 path
		ipv4 := &layers.IPv4{
			DstIP:    localHostNetIPv4,
			SrcIP:    endpoint.IP,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
		}
		ipH = ipv4
		networkLayer = ipv4
		localHostAddr = localHostNetIPv4
		isIPv4 = true
	} else {
		// IPv6 path
		ipv6 := &layers.IPv6{
			DstIP:      localHostNetIPv6,
			SrcIP:      endpoint.IP,
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolUDP,
		}
		ipH = ipv6
		networkLayer = ipv6
		localHostAddr = localHostNetIPv6
		isIPv4 = false
	}

	udpH := &layers.UDP{
		SrcPort: layers.UDPPort(endpoint.Port),
		DstPort: layers.UDPPort(localWGListenPort),
	}

	if err := udpH.SetNetworkLayerForChecksum(networkLayer); err != nil {
		return nil, fmt.Errorf("set network layer for checksum: %w", err)
	}

	return &PacketHeaders{
		ipH:           ipH,
		udpH:          udpH,
		layerBuffer:   gopacket.NewSerializeBuffer(),
		localHostAddr: localHostAddr,
		isIPv4:        isIPv4,
	}, nil
}

// ProxyWrapper help to keep the remoteConn instance for net.Conn.Close function call
type ProxyWrapper struct {
	wgeBPFProxy *WGEBPFProxy

	remoteConn net.Conn
	ctx        context.Context
	cancel     context.CancelFunc

	wgRelayedEndpointAddr *net.UDPAddr
	headers               *PacketHeaders
	headerCurrentUsed     *PacketHeaders
	rawConn               net.PacketConn

	paused     bool
	pausedCond *sync.Cond
	isStarted  bool

	closeListener *listener.CloseListener
}

func NewProxyWrapper(proxy *WGEBPFProxy) *ProxyWrapper {
	return &ProxyWrapper{
		wgeBPFProxy:   proxy,
		pausedCond:    sync.NewCond(&sync.Mutex{}),
		closeListener: listener.NewCloseListener(),
	}
}

func (p *ProxyWrapper) AddTurnConn(ctx context.Context, _ *net.UDPAddr, remoteConn net.Conn) error {
	addr, err := p.wgeBPFProxy.AddTurnConn(remoteConn)
	if err != nil {
		return fmt.Errorf("add turn conn: %w", err)
	}

	headers, err := NewPacketHeaders(p.wgeBPFProxy.localWGListenPort, addr)
	if err != nil {
		return fmt.Errorf("create packet sender: %w", err)
	}

	// Check if required raw connection is available
	if !headers.isIPv4 && p.wgeBPFProxy.rawConnIPv6 == nil {
		return errIPv6ConnNotAvailable
	}
	if headers.isIPv4 && p.wgeBPFProxy.rawConnIPv4 == nil {
		return errIPv4ConnNotAvailable
	}

	p.remoteConn = remoteConn
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.wgRelayedEndpointAddr = addr
	p.headers = headers
	p.rawConn = p.selectRawConn(headers)
	return nil
}

func (p *ProxyWrapper) EndpointAddr() *net.UDPAddr {
	return p.wgRelayedEndpointAddr
}

func (p *ProxyWrapper) SetDisconnectListener(disconnected func()) {
	p.closeListener.SetCloseListener(disconnected)
}

func (p *ProxyWrapper) Work() {
	if p.remoteConn == nil {
		return
	}

	p.pausedCond.L.Lock()
	p.paused = false

	p.headerCurrentUsed = p.headers
	p.rawConn = p.selectRawConn(p.headerCurrentUsed)

	if !p.isStarted {
		p.isStarted = true
		go p.proxyToLocal(p.ctx)
	}

	p.pausedCond.Signal()
	p.pausedCond.L.Unlock()
}

func (p *ProxyWrapper) Pause() {
	if p.remoteConn == nil {
		return
	}

	log.Tracef("pause proxy reading from: %s", p.remoteConn.RemoteAddr())
	p.pausedCond.L.Lock()
	p.paused = true
	p.pausedCond.L.Unlock()
}

func (p *ProxyWrapper) RedirectAs(endpoint *net.UDPAddr) {
	if endpoint == nil || endpoint.IP == nil {
		log.Errorf("failed to start package redirection, endpoint is nil")
		return
	}

	header, err := NewPacketHeaders(p.wgeBPFProxy.localWGListenPort, endpoint)
	if err != nil {
		log.Errorf("failed to create packet headers: %s", err)
		return
	}

	// Check if required raw connection is available
	if !header.isIPv4 && p.wgeBPFProxy.rawConnIPv6 == nil {
		log.Error(errIPv6ConnNotAvailable)
		return
	}
	if header.isIPv4 && p.wgeBPFProxy.rawConnIPv4 == nil {
		log.Error(errIPv4ConnNotAvailable)
		return
	}

	p.pausedCond.L.Lock()
	p.paused = false

	p.headerCurrentUsed = header
	p.rawConn = p.selectRawConn(header)

	p.pausedCond.Signal()
	p.pausedCond.L.Unlock()
}

// CloseConn close the remoteConn and automatically remove the conn instance from the map
func (p *ProxyWrapper) CloseConn() error {
	if p.cancel == nil {
		return fmt.Errorf("proxy not started")
	}

	p.cancel()

	p.closeListener.SetCloseListener(nil)

	p.pausedCond.L.Lock()
	p.paused = false
	p.pausedCond.Signal()
	p.pausedCond.L.Unlock()

	if err := p.remoteConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to close remote conn: %w", err)
	}
	return nil
}

func (p *ProxyWrapper) proxyToLocal(ctx context.Context) {
	defer p.wgeBPFProxy.removeTurnConn(uint16(p.wgRelayedEndpointAddr.Port))

	buf := make([]byte, p.wgeBPFProxy.mtu+bufsize.WGBufferOverhead)
	for {
		n, err := p.readFromRemote(ctx, buf)
		if err != nil {
			return
		}

		p.pausedCond.L.Lock()
		for p.paused {
			p.pausedCond.Wait()
		}

		err = p.sendPkg(buf[:n], p.headerCurrentUsed)
		p.pausedCond.L.Unlock()

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("failed to write out turn pkg to local conn: %v", err)
		}
	}
}

func (p *ProxyWrapper) readFromRemote(ctx context.Context, buf []byte) (int, error) {
	n, err := p.remoteConn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		p.closeListener.Notify()
		if !errors.Is(err, io.EOF) {
			log.Errorf("failed to read from turn conn (endpoint: :%d): %s", p.wgRelayedEndpointAddr.Port, err)
		}
		return 0, err
	}
	return n, nil
}

func (p *ProxyWrapper) sendPkg(data []byte, header *PacketHeaders) error {
	defer func() {
		if err := header.layerBuffer.Clear(); err != nil {
			log.Errorf("failed to clear layer buffer: %s", err)
		}
	}()

	payload := gopacket.Payload(data)

	if err := gopacket.SerializeLayers(header.layerBuffer, serializeOpts, header.ipH, header.udpH, payload); err != nil {
		return fmt.Errorf("serialize layers: %w", err)
	}

	if _, err := p.rawConn.WriteTo(header.layerBuffer.Bytes(), &net.IPAddr{IP: header.localHostAddr}); err != nil {
		return fmt.Errorf("write to raw conn: %w", err)
	}
	return nil
}

func (p *ProxyWrapper) selectRawConn(header *PacketHeaders) net.PacketConn {
	if header.isIPv4 {
		return p.wgeBPFProxy.rawConnIPv4
	}
	return p.wgeBPFProxy.rawConnIPv6
}
