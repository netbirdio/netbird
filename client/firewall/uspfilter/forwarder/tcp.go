package forwarder

import (
	"fmt"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// handleTCP is called by the TCP forwarder for new connections.
func (f *Forwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()

	dstAddr := id.LocalAddress
	dstPort := id.LocalPort
	dialAddr := fmt.Sprintf("%s:%d", dstAddr.String(), dstPort)

	// Dial the destination first
	dialer := net.Dialer{}
	outConn, err := dialer.Dial("tcp", dialAddr)
	if err != nil {
		r.Complete(true)
		return
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}

	ep, err2 := r.CreateEndpoint(&wq)
	if err2 != nil {
		if err := outConn.Close(); err != nil {
			log.Errorf("forwarder: outConn close error: %v", err)
		}
		r.Complete(true)
		return
	}

	// Now that we've successfully connected to the destination,
	// we can complete the incoming connection
	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	go f.proxyTCP(inConn, outConn)
}

func (f *Forwarder) proxyTCP(inConn *gonet.TCPConn, outConn net.Conn) {
	defer func() {
		if err := inConn.Close(); err != nil {
			log.Errorf("forwarder: inConn close error: %v", err)
		}
		if err := outConn.Close(); err != nil {
			log.Errorf("forwarder: outConn close error: %v", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(outConn, inConn)
		if err != nil {
			log.Errorf("proxyTCP: copy error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(inConn, outConn)
		if err != nil {
			log.Errorf("proxyTCP: copy error: %v", err)
		}
	}()

	wg.Wait()
}
