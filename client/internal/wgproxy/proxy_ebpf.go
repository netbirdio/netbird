//go:build linux && !android

package wgproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ebpf"
	ebpfMgr "github.com/netbirdio/netbird/client/internal/ebpf/manager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

// WGEBPFProxy definition for proxy with EBPF support
type WGEBPFProxy struct {
	ebpfManager ebpfMgr.Manager

	ctx    context.Context
	cancel context.CancelFunc

	lastUsedPort      uint16
	localWGListenPort int

	turnConnStore map[uint16]net.Conn
	turnConnMutex sync.Mutex

	rawConn net.PacketConn
	conn    transport.UDPConn
}

// NewWGEBPFProxy create new WGEBPFProxy instance
func NewWGEBPFProxy(ctx context.Context, wgPort int) *WGEBPFProxy {
	log.Debugf("instantiate ebpf proxy")
	wgProxy := &WGEBPFProxy{
		localWGListenPort: wgPort,
		ebpfManager:       ebpf.GetEbpfManagerInstance(),
		lastUsedPort:      0,
		turnConnStore:     make(map[uint16]net.Conn),
	}
	wgProxy.ctx, wgProxy.cancel = context.WithCancel(ctx)

	return wgProxy
}

// listen load ebpf program and listen the proxy
func (p *WGEBPFProxy) listen() error {
	pl := portLookup{}
	wgPorxyPort, err := pl.searchFreePort()
	if err != nil {
		return err
	}

	p.rawConn, err = p.prepareSenderRawSocket()
	if err != nil {
		return err
	}

	err = p.ebpfManager.LoadWgProxy(wgPorxyPort, p.localWGListenPort)
	if err != nil {
		return err
	}

	addr := net.UDPAddr{
		Port: wgPorxyPort,
		IP:   net.ParseIP("127.0.0.1"),
	}

	conn, err := nbnet.ListenUDP("udp", &addr)
	if err != nil {
		cErr := p.Free()
		if cErr != nil {
			log.Errorf("Failed to close the wgproxy: %s", cErr)
		}
		return err
	}
	p.conn = conn

	go p.proxyToRemote()
	log.Infof("local wg proxy listening on: %d", wgPorxyPort)
	return nil
}

// AddTurnConn add new turn connection for the proxy
func (p *WGEBPFProxy) AddTurnConn(turnConn net.Conn) (net.Addr, error) {
	wgEndpointPort, err := p.storeTurnConn(turnConn)
	if err != nil {
		return nil, err
	}

	go p.proxyToLocal(wgEndpointPort, turnConn)
	log.Infof("turn conn added to wg proxy store: %s, endpoint port: :%d", turnConn.RemoteAddr(), wgEndpointPort)

	wgEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: int(wgEndpointPort),
	}
	return wgEndpoint, nil
}

// CloseConn doing nothing because this type of proxy implementation does not store the connection
func (p *WGEBPFProxy) CloseConn() error {
	return nil
}

// Free resources
func (p *WGEBPFProxy) Free() error {
	log.Debugf("free up ebpf wg proxy")
	var err1, err2, err3 error
	if p.conn != nil {
		err1 = p.conn.Close()
	}

	err2 = p.ebpfManager.FreeWGProxy()
	if p.rawConn != nil {
		err3 = p.rawConn.Close()
	}

	if err1 != nil {
		return err1
	}

	if err2 != nil {
		return err2
	}

	return err3
}

func (p *WGEBPFProxy) proxyToLocal(endpointPort uint16, remoteConn net.Conn) {
	buf := make([]byte, 1500)
	var err error
	defer func() {
		p.removeTurnConn(endpointPort)
	}()
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			var n int
			n, err = remoteConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Errorf("failed to read from turn conn (endpoint: :%d): %s", endpointPort, err)
				}
				return
			}
			err = p.sendPkg(buf[:n], endpointPort)
			if err != nil {
				log.Errorf("failed to write out turn pkg to local conn: %v", err)
			}
		}
	}
}

// proxyToRemote read messages from local WireGuard interface and forward it to remote conn
func (p *WGEBPFProxy) proxyToRemote() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			n, addr, err := p.conn.ReadFromUDP(buf)
			if err != nil {
				log.Errorf("failed to read UDP pkg from WG: %s", err)
				return
			}

			p.turnConnMutex.Lock()
			conn, ok := p.turnConnStore[uint16(addr.Port)]
			p.turnConnMutex.Unlock()
			if !ok {
				log.Infof("turn conn not found by port: %d", addr.Port)
				continue
			}

			_, err = conn.Write(buf[:n])
			if err != nil {
				log.Debugf("failed to forward local wg pkg (%d) to remote turn conn: %s", addr.Port, err)
			}
		}
	}
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
	log.Tracef("remove turn conn from store by port: %d", turnConnID)
	p.turnConnMutex.Lock()
	defer p.turnConnMutex.Unlock()
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

func (p *WGEBPFProxy) prepareSenderRawSocket() (net.PacketConn, error) {
	// Create a raw socket.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket failed: %w", err)
	}

	// Set the IP_HDRINCL option on the socket to tell the kernel that headers are included in the packet.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return nil, fmt.Errorf("setting IP_HDRINCL failed: %w", err)
	}

	// Bind the socket to the "lo" interface.
	err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lo")
	if err != nil {
		return nil, fmt.Errorf("binding to lo interface failed: %w", err)
	}

	// Set the fwmark on the socket.
	err = nbnet.SetSocketOpt(fd)
	if err != nil {
		return nil, fmt.Errorf("setting fwmark failed: %w", err)
	}

	// Convert the file descriptor to a PacketConn.
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	if file == nil {
		return nil, fmt.Errorf("converting fd to file failed")
	}
	packetConn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, fmt.Errorf("converting file to packet conn failed: %w", err)
	}

	return packetConn, nil
}

func (p *WGEBPFProxy) sendPkg(data []byte, port uint16) error {
	localhost := net.ParseIP("127.0.0.1")

	payload := gopacket.Payload(data)
	ipH := &layers.IPv4{
		DstIP:    localhost,
		SrcIP:    localhost,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	udpH := &layers.UDP{
		SrcPort: layers.UDPPort(port),
		DstPort: layers.UDPPort(p.localWGListenPort),
	}

	err := udpH.SetNetworkLayerForChecksum(ipH)
	if err != nil {
		return fmt.Errorf("set network layer for checksum: %w", err)
	}

	layerBuffer := gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(layerBuffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ipH, udpH, payload)
	if err != nil {
		return fmt.Errorf("serialize layers: %w", err)
	}
	if _, err = p.rawConn.WriteTo(layerBuffer.Bytes(), &net.IPAddr{IP: localhost}); err != nil {
		return fmt.Errorf("write to raw conn: %w", err)
	}
	return nil
}
