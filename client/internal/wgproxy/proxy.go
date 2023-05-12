package wgproxy

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
)

type WGProxy struct {
	listenPort int
	ebpf       *eBPF

	conn              *net.UDPConn
	lastUsedPort      int
	localWGListenAddr *net.UDPAddr

	// todo: it is not thread safe
	conns map[int]net.Conn
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
		conns:             make(map[int]net.Conn),
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

func (p *WGProxy) TurnConn(conn net.Conn) (net.Addr, error) {
	localWgDstPort := p.nextFreePort()

	srcAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: localWgDstPort,
	}

	localConn, err := net.DialUDP("udp", srcAddress, p.localWGListenAddr)
	if err != nil {
		return nil, err
	}

	p.conns[localWgDstPort] = conn

	go p.proxyToLocal(localConn, conn)
	log.Debugf("turn conn added to local proxy")
	return localConn.LocalAddr(), nil
}

// todo error handling
func (p *WGProxy) proxyToLocal(localConn, remoteConn net.Conn) {
	for {
		buf := make([]byte, 1500)
		n, err := remoteConn.Read(buf)
		if err != nil {
			log.Errorf("failed to read from UDP: %s", err)
			continue
		}
		log.Tracef("received pkg from turn: %d", n)

		_, err = localConn.Write(buf[:n])
		if err != nil {
			log.Debugf("failed to write out turn pkg to local conn: %v", err)
		}
	}
}

// proxyToRemote read messages from local WireGuard interface and forward it to remote conn
func (p *WGProxy) proxyToRemote() {
	for {
		buf := make([]byte, 1500)
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			log.Errorf("failed to read from UDP: %s", err)
			continue
		}

		conn, ok := p.conns[addr.Port]
		if !ok {
			log.Errorf("local conn not found by port: %d", addr.Port)
			continue
		}

		log.Tracef("forward local wg pgk to turn conn: %d", n)

		_, err = conn.Write(buf[:n])
		if err != nil {
			log.Debugf("failed to forward local wg pkg to remote turn conn: %v", err)
		}
	}
}

// todo threadSafe
// todo handle overflow
func (p *WGProxy) nextFreePort() int {
	p.lastUsedPort++
	return p.lastUsedPort
}
