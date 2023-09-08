//go:build linux && !android

package wgproxy

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ebpf"
	ebpfMgr "github.com/netbirdio/netbird/client/internal/ebpf/manager"
)

// WGEBPFProxy definition for proxy with EBPF support
type WGEBPFProxy struct {
	ebpfManager       ebpfMgr.Manager
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
		ebpfManager:       ebpf.GetEbpfManagerInstance(),
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

	err = p.ebpfManager.LoadWgProxy(wgPorxyPort, p.localWGListenPort)
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
		if cErr != nil {
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
	for {
		n, err := remoteConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Errorf("failed to read from turn conn (endpoint: :%d): %s", endpointPort, err)
			}
			p.removeTurnConn(endpointPort)
			log.Infof("stop forward turn packages to port: %d. error: %s", endpointPort, err)
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
	buf := make([]byte, 1500)
	for {
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
		return err
	}

	layerBuffer := gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(layerBuffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ipH, udpH, payload)
	if err != nil {
		return err
	}
	_, err = p.rawConn.WriteTo(layerBuffer.Bytes(), &net.IPAddr{IP: localhost})
	return err
}
