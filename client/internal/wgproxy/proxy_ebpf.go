//go:build linux && !android

package wgproxy

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	log "github.com/sirupsen/logrus"
)

// WGEBPFProxy definition for proxy with eBPF support
type WGEBPFProxy struct {
	ebpf              *eBPF
	lastUsedPort      uint16
	localWGListenPort int

	turnConnStore map[uint16]net.Conn
	turnConnMutex sync.Mutex

	rawConn net.PacketConn
	conn    *net.UDPConn
}

// NewWGEBPFProxy create new WGEBPFProxy instance
func NewWGEBPFProxy(wgPort int) *WGEBPFProxy {
	log.Debugf("instantiate ebpf proxy")
	wgProxy := &WGEBPFProxy{
		localWGListenPort: wgPort,
		ebpf:              newEBPF(),
		lastUsedPort:      0,
		turnConnStore:     make(map[uint16]net.Conn),
	}
	return wgProxy
}

// Listen load ebpf program and listen the proxy
func (p *WGEBPFProxy) Listen() error {
	pl := portLookup{}
	wgPorxyPort, err := pl.searchFreePort()
	if err != nil {
		return err
	}

	p.rawConn, err = p.prepareSenderRawSocket()
	if err != nil {
		return err
	}

	err = p.ebpf.load(wgPorxyPort, p.localWGListenPort)
	if err != nil {
		return err
	}

	addr := net.UDPAddr{
		Port: wgPorxyPort,
		IP:   net.ParseIP("127.0.0.1"),
	}

	p.conn, err = net.ListenUDP("udp", &addr)
	if err != nil {
		cErr := p.Free()
		if err != nil {
			log.Errorf("failed to close the wgproxy: %s", cErr)
		}
		return err
	}

	go p.proxyToRemote()
	log.Infof("local wg proxy listening on: %d", wgPorxyPort)
	return nil
}

// AddTurnConn add new turn connection for the proxy
func (p *WGEBPFProxy) AddTurnConn(turnConn net.Conn) (net.Addr, error) {
	wgEndpointPort := p.storeTurnConn(turnConn)

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
	var err1, err2 error
	if p.conn != nil {
		err1 = p.conn.Close()
	}

	err2 = p.ebpf.free()
	if p.rawConn != nil {
		err2 = p.rawConn.Close()
	}

	if err1 != nil {
		return err1
	}

	return err2
}

func (p *WGEBPFProxy) proxyToLocal(endpointPort uint16, remoteConn net.Conn) {
	for {
		buf := make([]byte, 1500)
		n, err := remoteConn.Read(buf)
		if err != nil {
			log.Errorf("failed to read from turn conn (endpoint: :%d): %s", endpointPort, err)
			p.removeTurnConn(endpointPort)
			return
		}
		err = p.sendPkg(buf[:n], endpointPort)
		if err != nil {
			log.Errorf("failed to write out turn pkg to local conn: %v", err)
		}
	}
}

// proxyToRemote read messages from local WireGuard interface and forward it to remote conn
func (p *WGEBPFProxy) proxyToRemote() {
	for {
		buf := make([]byte, 1500)
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			log.Errorf("failed to read UDP pkg from WG: %s", err)
			return
		}

		conn, ok := p.turnConnStore[uint16(addr.Port)]
		if !ok {
			log.Errorf("turn conn not found by port: %d", addr.Port)
			continue
		}

		_, err = conn.Write(buf[:n])
		if err != nil {
			log.Debugf("failed to forward local wg pkg (%d) to remote turn conn: %s", addr.Port, err)
		}
	}
}

func (p *WGEBPFProxy) storeTurnConn(turnConn net.Conn) uint16 {
	p.turnConnMutex.Lock()
	defer p.turnConnMutex.Unlock()

	port := p.nextFreePort()
	p.turnConnStore[port] = turnConn
	return port
}

func (p *WGEBPFProxy) removeTurnConn(turnConnID uint16) {
	log.Tracef("remove turn conn from store by port: %d", turnConnID)
	p.turnConnMutex.Lock()
	defer p.turnConnMutex.Unlock()
	delete(p.turnConnStore, turnConnID)

}

func (p *WGEBPFProxy) nextFreePort() uint16 {
	p.lastUsedPort = p.lastUsedPort + 1 | 1
	return p.lastUsedPort
}

func (p *WGEBPFProxy) prepareSenderRawSocket() (net.PacketConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return nil, err
	}
	err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lo")
	if err != nil {
		return nil, err
	}

	return net.FilePacketConn(os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd)))
}

func (p *WGEBPFProxy) sendPkg(data []byte, port uint16) error {
	localhost := net.ParseIP("127.0.0.1")

	buffer := gopacket.NewSerializeBuffer()
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

	if err := udpH.SetNetworkLayerForChecksum(ipH); err != nil {
		return err
	}
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ipH, udpH, payload)
	if err != nil {
		return err
	}
	_, err = p.rawConn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: localhost})
	return err
}
