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

type WGProxy struct {
	listenPort        int
	ebpf              *eBPF
	lastUsedPort      uint16
	localWGListenAddr *net.UDPAddr

	turnConnStore map[uint16]net.Conn
	turnConnMutex sync.Mutex

	rawConn net.PacketConn
	conn    *net.UDPConn
}

// NewWGProxy
// todo: lookup a free listenPort
// todo: use wg filterPort in ebpf instead of hardcoded
// todo: remove hardocded 8081 proxy port from ebpf
func NewWGProxy(proxyPort int, wgPort int) (*WGProxy, error) {
	wgLAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", wgPort))
	if err != nil {
		return nil, err
	}
	wgProxy := &WGProxy{
		listenPort:        proxyPort,
		localWGListenAddr: wgLAddr,
		ebpf:              newEBPF(),
		lastUsedPort:      0,
		turnConnStore:     make(map[uint16]net.Conn),
	}
	return wgProxy, nil
}

func (p *WGProxy) Listen() error {
	var err error
	p.rawConn, err = p.prepareSenderRawSocket()
	if err != nil {
		return err
	}

	err = p.ebpf.load()
	if err != nil {
		return err
	}

	addr := net.UDPAddr{
		Port: p.listenPort,
		IP:   net.ParseIP("127.0.0.1"),
	}

	p.conn, err = net.ListenUDP("udp", &addr)
	if err != nil {
		cErr := p.Close()
		if err != nil {
			log.Errorf("failed to close the wgproxy: %s", cErr)
		}
		return err
	}

	go p.proxyToRemote()
	log.Infof("local wg proxy listening on: %d", p.listenPort)
	return nil
}

func (p *WGProxy) TurnConn(turnConn net.Conn) (net.Addr, error) {
	wgEndpointPort := p.storeTurnConn(turnConn)

	go p.proxyToLocal(wgEndpointPort, turnConn)
	log.Infof("turn conn added to wg proxy store: %s, endpoint port: :%d", turnConn.RemoteAddr(), wgEndpointPort)

	wgEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: int(wgEndpointPort),
	}
	return wgEndpoint, nil
}

func (p *WGProxy) Close() error {
	var err1, err2, err3 error
	if p.conn != nil {
		err1 = p.conn.Close()
	}

	err2 = p.ebpf.free()
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

func (p *WGProxy) proxyToLocal(endpointPort uint16, remoteConn net.Conn) {
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
func (p *WGProxy) proxyToRemote() {
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

func (p *WGProxy) storeTurnConn(turnConn net.Conn) uint16 {
	p.turnConnMutex.Lock()
	p.turnConnMutex.Unlock()

	port := p.nextFreePort()
	p.turnConnStore[port] = turnConn
	return port
}

func (p *WGProxy) removeTurnConn(turnConnID uint16) {
	log.Tracef("remove turn conn from store by port: %d", turnConnID)
	p.turnConnMutex.Lock()
	p.turnConnMutex.Unlock()
	delete(p.turnConnStore, turnConnID)

}

func (p *WGProxy) nextFreePort() uint16 {
	p.lastUsedPort = p.lastUsedPort + 1 | 1
	return p.lastUsedPort
}

func (p *WGProxy) prepareSenderRawSocket() (net.PacketConn, error) {
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

func (p *WGProxy) sendPkg(data []byte, port uint16) error {
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
		DstPort: layers.UDPPort(p.localWGListenAddr.Port),
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
