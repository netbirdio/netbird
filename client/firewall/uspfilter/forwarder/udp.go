package forwarder

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	udpTimeout = 60 * time.Second
)

type udpPacketConn struct {
	conn     *gonet.UDPConn
	outConn  net.Conn
	lastTime time.Time
}

type udpForwarder struct {
	sync.RWMutex
	conns map[string]*udpPacketConn
}

func newUDPForwarder() *udpForwarder {
	f := &udpForwarder{
		conns: make(map[string]*udpPacketConn),
	}
	go f.cleanup()
	return f
}

// cleanup periodically removes idle UDP connections
func (f *udpForwarder) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		f.Lock()
		now := time.Now()
		for addr, conn := range f.conns {
			if now.Sub(conn.lastTime) > udpTimeout {
				conn.conn.Close()
				conn.outConn.Close()
				delete(f.conns, addr)
			}
		}
		f.Unlock()
	}
}

// handleUDP is called by the UDP forwarder for new packets
func (f *Forwarder) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}

	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Errorf("Create UDP endpoint error: %v", err)
		return
	}

	inConn := gonet.NewUDPConn(f.stack, &wq, ep)

	// Try to get existing connection or create a new one
	f.udpForwarder.Lock()
	pConn, exists := f.udpForwarder.conns[dstAddr]
	if !exists {
		outConn, err := net.Dial("udp", dstAddr)
		if err != nil {
			f.udpForwarder.Unlock()
			if err := inConn.Close(); err != nil {
				log.Errorf("forwader: UDP inConn close error: %v", err)
			}
			log.Errorf("forwarder> UDP dial error: %v", err)
			return
		}

		pConn = &udpPacketConn{
			conn:     inConn,
			outConn:  outConn,
			lastTime: time.Now(),
		}
		f.udpForwarder.conns[dstAddr] = pConn

		go f.proxyUDP(pConn, dstAddr)
	}
	f.udpForwarder.Unlock()
}

func (f *Forwarder) proxyUDP(pConn *udpPacketConn, dstAddr string) {
	defer func() {
		if err := pConn.conn.Close(); err != nil {
			log.Errorf("forwarder: inConn close error: %v", err)
		}
		if err := pConn.outConn.Close(); err != nil {
			log.Errorf("forwarder: outConn close error: %v", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Handle outbound to inbound traffic
	go func() {
		defer wg.Done()
		f.copyUDP(pConn.conn, pConn.outConn, dstAddr, "outbound->inbound")
	}()

	// Handle inbound to outbound traffic
	go func() {
		defer wg.Done()
		f.copyUDP(pConn.outConn, pConn.conn, dstAddr, "inbound->outbound")
	}()

	wg.Wait()

	// Clean up the connection from the map
	f.udpForwarder.Lock()
	delete(f.udpForwarder.conns, dstAddr)
	f.udpForwarder.Unlock()
}

func (f *Forwarder) copyUDP(dst net.Conn, src net.Conn, dstAddr, direction string) {
	buffer := make([]byte, 65535)
	for {
		n, err := src.Read(buffer)
		if err != nil {
			log.Errorf("UDP %s read error: %v", direction, err)
			return
		}

		_, err = dst.Write(buffer[:n])
		if err != nil {
			log.Errorf("UDP %s write error: %v", direction, err)
			continue
		}

		f.udpForwarder.Lock()
		if conn, ok := f.udpForwarder.conns[dstAddr]; ok {
			conn.lastTime = time.Now()
		}
		f.udpForwarder.Unlock()
	}
}
