//go:build linux && !android

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"

	"github.com/netbirdio/netbird/client/iface/bufsize"
	"github.com/netbirdio/netbird/client/iface/wgproxy/listener"
)

// injectBatchSize bounds how many relayed packets are drained and injected into
// the local WireGuard socket per sendmmsg. Matches wireguard-go's IdealBatchSize.
const injectBatchSize = 128

// batchReader is the optional interface a relay conn implements to hand several
// packets over in one call (satisfied structurally by the relay client *Conn).
type batchReader interface {
	ReadBatch(bufs [][]byte, sizes []int) (n int, err error)
}

// batchWriteConn is the subset of x/net ipv4/ipv6 PacketConn used to write a
// batch of packets with one sendmmsg. ipv4.Message and ipv6.Message are the same
// underlying type, so both PacketConns satisfy this with []ipv4.Message.
type batchWriteConn interface {
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

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

	// batchInject enables draining several relayed packets and injecting them
	// with one sendmmsg. Gated by NB_RELAY_INJECT_BATCH so the per-packet path
	// stays the default until the batch path is proven in the field.
	batchInject bool

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
	p.batchInject = os.Getenv("NB_RELAY_INJECT_BATCH") == "true"
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

// InjectPacket writes b to the remote peer over the underlying transport.
func (p *ProxyWrapper) InjectPacket(b []byte) error {
	if p.remoteConn == nil {
		return errors.New("proxy not started")
	}
	if _, err := p.remoteConn.Write(b); err != nil {
		return err
	}
	return nil
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

	if p.batchInject {
		if br, ok := p.remoteConn.(batchReader); ok {
			p.proxyToLocalBatch(ctx, br)
			return
		}
	}

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

// proxyToLocalBatch drains up to injectBatchSize relayed packets per wake and
// injects them into the local WireGuard socket with a single sendmmsg. Blocks
// for the first packet, then takes whatever is already queued, so a steady flow
// batches while a sparse one still injects each packet immediately.
func (p *ProxyWrapper) proxyToLocalBatch(ctx context.Context, br batchReader) {
	bufSize := int(p.wgeBPFProxy.mtu) + bufsize.WGBufferOverhead
	bufs := make([][]byte, injectBatchSize)
	sizes := make([]int, injectBatchSize)
	sbs := make([]gopacket.SerializeBuffer, injectBatchSize)
	msgs := make([]ipv4.Message, injectBatchSize)
	for i := range bufs {
		bufs[i] = make([]byte, bufSize)
		sbs[i] = gopacket.NewSerializeBuffer()
		msgs[i].Buffers = make([][]byte, 1)
	}

	for {
		n, err := br.ReadBatch(bufs, sizes)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.closeListener.Notify()
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Errorf("failed to read batch from turn conn (endpoint: :%d): %s", p.wgRelayedEndpointAddr.Port, err)
			}
			return
		}

		p.pausedCond.L.Lock()
		for p.paused {
			p.pausedCond.Wait()
		}
		header := p.headerCurrentUsed
		batchConn := p.selectBatchConn(header)
		werr := p.sendBatch(header, batchConn, bufs, sizes, n, sbs, msgs)
		p.pausedCond.L.Unlock()

		if werr != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("failed to write out turn batch to local conn: %v", werr)
		}
	}
}

// sendBatch serializes n packets (each into its own reused buffer, since lengths
// and checksums differ) and writes them with one or more WriteBatch calls.
func (p *ProxyWrapper) sendBatch(header *PacketHeaders, batchConn batchWriteConn, bufs [][]byte, sizes []int, n int, sbs []gopacket.SerializeBuffer, msgs []ipv4.Message) error {
	if batchConn == nil {
		return errors.New("batch conn not available")
	}
	dstAddr := &net.IPAddr{IP: header.localHostAddr}
	for i := 0; i < n; i++ {
		payload := gopacket.Payload(bufs[i][:sizes[i]])
		if err := gopacket.SerializeLayers(sbs[i], serializeOpts, header.ipH, header.udpH, payload); err != nil {
			return fmt.Errorf("serialize layers: %w", err)
		}
		msgs[i].Buffers[0] = sbs[i].Bytes()
		msgs[i].Addr = dstAddr
		msgs[i].N = 0
	}

	var werr error
	for off := 0; off < n; {
		w, err := batchConn.WriteBatch(msgs[off:n], 0)
		if err != nil {
			werr = err
			break
		}
		if w <= 0 {
			werr = fmt.Errorf("write batch made no progress at %d/%d", off, n)
			break
		}
		off += w
	}

	for i := 0; i < n; i++ {
		if err := sbs[i].Clear(); err != nil {
			log.Errorf("failed to clear layer buffer: %s", err)
		}
	}
	return werr
}

func (p *ProxyWrapper) selectBatchConn(header *PacketHeaders) batchWriteConn {
	if header.isIPv4 {
		if p.wgeBPFProxy.batchConnIPv4 == nil {
			return nil
		}
		return p.wgeBPFProxy.batchConnIPv4
	}
	if p.wgeBPFProxy.batchConnIPv6 == nil {
		return nil
	}
	return p.wgeBPFProxy.batchConnIPv6
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
