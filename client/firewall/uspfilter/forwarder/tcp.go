package forwarder

import (
	"context"
	"fmt"
	"io"
	"net"

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

	outConn, err := (&net.Dialer{}).DialContext(f.ctx, "tcp", dialAddr)
	if err != nil {
		r.Complete(true)
		f.logger.Trace("forwarder: dial error for %v: %v", id, err)
		return
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}

	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		if err := outConn.Close(); err != nil {
			f.logger.Error("forwarder: outConn close error: %v", err)
		}
		r.Complete(true)
		return
	}

	// Complete the handshake
	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	f.logger.Trace("forwarder: established TCP connection to %v", id)

	go f.proxyTCP(inConn, outConn)
}

func (f *Forwarder) proxyTCP(inConn *gonet.TCPConn, outConn net.Conn) {
	defer func() {
		if err := inConn.Close(); err != nil {
			f.logger.Error("forwarder: inConn close error: %v", err)
		}
		if err := outConn.Close(); err != nil {
			f.logger.Error("forwarder: outConn close error: %v", err)
		}
	}()

	// Create context for managing the proxy goroutines
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()

	errChan := make(chan error, 2)

	go func() {
		n, err := io.Copy(outConn, inConn)
		if err != nil && !isClosedError(err) {
			f.logger.Error("inbound->outbound copy error after %d bytes: %v", n, err)
		}
		errChan <- err
	}()

	go func() {
		n, err := io.Copy(inConn, outConn)
		if err != nil && !isClosedError(err) {
			f.logger.Error("outbound->inbound copy error after %d bytes: %v", n, err)
		}
		errChan <- err
	}()

	select {
	case <-ctx.Done():
		return
	case err := <-errChan:
		if err != nil && !isClosedError(err) {
			f.logger.Error("proxyTCP: copy error: %v", err)
		}
		return
	}
}
