// Package stun provides an embedded STUN server for NAT traversal discovery.
package stun

import (
	"context"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pion/stun/v3"
)

// Server implements a STUN server that responds to binding requests
// with the client's reflexive transport address.
type Server struct {
	address string
	conn    *net.UDPConn
	logger  *log.Entry

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewServer creates a new STUN server that will listen on the given address.
// The address should be in the form "host:port" or ":port".
func NewServer(address string) *Server {
	return &Server{
		address: address,
		logger:  log.WithField("component", "stun-server"),
	}
}

// Listen starts the STUN server and blocks until the context is cancelled
// or an error occurs.
func (s *Server) Listen(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	addr, err := net.ResolveUDPAddr("udp", s.address)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	s.conn = conn

	s.logger.Infof("STUN server listening on %s", s.address)

	// Handle incoming packets
	s.wg.Add(1)
	go s.readLoop(ctx)

	<-ctx.Done()
	return nil
}

// readLoop continuously reads UDP packets and handles STUN requests.
func (s *Server) readLoop(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, 1500) // Standard MTU size
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			// Check if we're shutting down
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Warnf("failed to read UDP packet: %v", err)
				continue
			}
		}

		// Handle packet in the same goroutine to avoid complexity
		// STUN responses are small and fast
		s.handlePacket(buf[:n], remoteAddr)
	}
}

// handlePacket processes a STUN request and sends a response.
func (s *Server) handlePacket(data []byte, addr *net.UDPAddr) {
	// Check if it's a STUN message
	if !stun.IsMessage(data) {
		return
	}

	// Parse the STUN message
	msg := &stun.Message{Raw: data}
	if err := msg.Decode(); err != nil {
		s.logger.Debugf("failed to decode STUN message: %v", err)
		return
	}

	// Only handle binding requests
	if msg.Type != stun.BindingRequest {
		s.logger.Debugf("ignoring non-binding request: %s", msg.Type)
		return
	}

	s.logger.Debugf("received STUN binding request from %s", addr)

	// Build the response
	response, err := stun.Build(
		stun.NewTransactionIDSetter(msg.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{
			IP:   addr.IP,
			Port: addr.Port,
		},
		stun.Fingerprint,
	)
	if err != nil {
		s.logger.Errorf("failed to build STUN response: %v", err)
		return
	}

	// Send the response
	if _, err := s.conn.WriteToUDP(response.Raw, addr); err != nil {
		s.logger.Errorf("failed to send STUN response: %v", err)
		return
	}

	s.logger.Debugf("sent STUN binding response to %s with address %s:%d", addr, addr.IP, addr.Port)
}

// Shutdown gracefully stops the STUN server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down STUN server")

	if s.cancel != nil {
		s.cancel()
	}

	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			s.logger.Warnf("error closing UDP connection: %v", err)
		}
	}

	// Wait for readLoop to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("STUN server stopped")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
