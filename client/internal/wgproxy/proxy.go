package wgproxy

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

type WGProxy struct {
	listenPort int
	ebpf       *eBPF

	conn              *net.UDPConn
	lastUsedPort      uint16
	localWGListenAddr *net.UDPAddr

	turnConnStore map[uint16]net.Conn
	turnConnMutex sync.Mutex
}

// NewWGProxy
// todo: write close func
// todo: lookup a free listenPort
// todo: use wg filterPort in ebpf instead of hardcoded
// todo: remove hardocded 8081 proxy port from ebpf
func NewWGProxy(proxyPort int, wgPort int) (*WGProxy, error) {
	wgLAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", wgPort))
	if err != nil {
		return nil, err
	}

	return &WGProxy{
		listenPort:        proxyPort,
		localWGListenAddr: wgLAddr,
		ebpf:              newEBPF(),
		lastUsedPort:      0,
		turnConnStore:     make(map[uint16]net.Conn),
	}, nil
}

func (p *WGProxy) Listen() error {
	err := p.ebpf.load()
	if err != nil {
		return err
	}
	addr := net.UDPAddr{
		Port: p.listenPort,
		IP:   net.ParseIP("127.0.0.1"),
	}

	p.conn, err = net.ListenUDP("udp", &addr)
	if err != nil {
		return err
	}

	go p.proxyToRemote()
	log.Infof("local wg proxy listening on: %d", p.listenPort)
	return nil
}

func (p *WGProxy) TurnConn(turnConn net.Conn) (net.Addr, error) {
	wgEndpointPort := p.storeTurnConn(turnConn)
	wgEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: int(wgEndpointPort),
	}

	localConn, err := net.DialUDP("udp", wgEndpoint, p.localWGListenAddr)
	if err != nil {
		p.removeTurnConn(wgEndpointPort)
		return nil, err
	}

	go p.proxyToLocal(wgEndpointPort, localConn, turnConn)
	log.Debugf("turn conn added to wg proxy store: %s, port id: %d", turnConn.RemoteAddr(), wgEndpointPort)
	return localConn.LocalAddr(), nil
}

func (p *WGProxy) proxyToLocal(id uint16, localConn, remoteConn net.Conn) {
	for {
		buf := make([]byte, 1500)
		n, err := remoteConn.Read(buf)
		if err != nil {
			log.Errorf("failed to read from turn conn (%d): %s", id, err)
			p.removeTurnConn(id)
			return
		}

		_, err = localConn.Write(buf[:n])
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
			continue
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
