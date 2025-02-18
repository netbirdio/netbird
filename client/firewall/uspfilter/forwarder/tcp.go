package forwarder

import (
	"context"
	"fmt"
	"io"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// handleTCP is called by the TCP forwarder for new connections.
func (f *Forwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()

	dialAddr := fmt.Sprintf("%s:%d", f.determineDialAddr(id.LocalAddress), id.LocalPort)

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
		f.logger.Error("forwarder: failed to create TCP endpoint: %v", epErr)
		if err := outConn.Close(); err != nil {
			f.logger.Debug("forwarder: outConn close error: %v", err)
		}
		r.Complete(true)
		return
	}

	// Complete the handshake
	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	f.logger.Trace("forwarder: established TCP connection %v", id)

	go f.proxyTCP(id, inConn, outConn, ep)
}

func (f *Forwarder) proxyTCP(id stack.TransportEndpointID, inConn *gonet.TCPConn, outConn net.Conn, ep tcpip.Endpoint) {
	defer func() {
		if err := inConn.Close(); err != nil {
			f.logger.Debug("forwarder: inConn close error: %v", err)
		}
		if err := outConn.Close(); err != nil {
			f.logger.Debug("forwarder: outConn close error: %v", err)
		}
		ep.Close()
	}()

	// Create context for managing the proxy goroutines
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(outConn, inConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(inConn, outConn)
		errChan <- err
	}()

	select {
	case <-ctx.Done():
		f.logger.Trace("forwarder: tearing down TCP connection %v due to context done", id)
		return
	case err := <-errChan:
		if err != nil && !isClosedError(err) {
			f.logger.Error("proxyTCP: copy error: %v", err)
		}
		f.logger.Trace("forwarder: tearing down TCP connection %v", id)
		return
	}
}
