// Package stun provides an embedded STUN server for NAT traversal discovery.
package stun

import (
	"context"
	"errors"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pion/stun/v3"
)

// ErrServerClosed is returned by Listen when the server is shut down gracefully.
var ErrServerClosed = errors.New("stun: server closed")

// Server implements a STUN server that responds to binding requests
// with the client's reflexive transport address.
type Server struct {
	conn     *net.UDPConn
	logger   *log.Entry
	logLevel log.Level

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewServer creates a new STUN server with the given UDP listener.
// The caller is responsible for creating and providing the listener.
// logLevel can be: panic, fatal, error, warn, info, debug, trace
func NewServer(conn *net.UDPConn, logLevel string) *Server {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.InfoLevel
	}

	logger := log.WithField("component", "stun-server")
	logger.Infof("STUN server log level set to: %s", level.String())

	return &Server{
		conn:     conn,
		logger:   logger,
		logLevel: level,
	}
}

// Listen starts the STUN server and blocks until the server is shut down.
// Returns ErrServerClosed when shut down gracefully via Shutdown.
func (s *Server) Listen(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	s.logger.Infof("STUN server listening on %s", s.conn.LocalAddr())

	// Handle incoming packets
	s.wg.Add(1)
	go s.readLoop(ctx)

	s.wg.Wait()
	return ErrServerClosed
}

// readLoop continuously reads UDP packets and handles STUN requests.
func (s *Server) readLoop(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, 1500) // Standard MTU size
	for {
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
	s.logger.Debugf("received %d bytes from %s", len(data), addr)

	// Check if it's a STUN message
	if !stun.IsMessage(data) {
		s.logger.Debugf("not a STUN message (first bytes: %x)", data[:min(len(data), 8)])
		return
	}

	// Parse the STUN message
	msg := &stun.Message{Raw: data}
	if err := msg.Decode(); err != nil {
		s.logger.Warnf("failed to decode STUN message from %s: %v", addr, err)
		return
	}

	s.logger.Infof("received STUN %s from %s (tx=%x)", msg.Type, addr, msg.TransactionID[:8])

	// Only handle binding requests
	if msg.Type != stun.BindingRequest {
		s.logger.Debugf("ignoring non-binding request: %s", msg.Type)
		return
	}

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
	n, err := s.conn.WriteToUDP(response.Raw, addr)
	if err != nil {
		s.logger.Errorf("failed to send STUN response to %s: %v", addr, err)
		return
	}

	s.logger.Infof("sent STUN BindingSuccess to %s (%d bytes) with XORMappedAddress %s:%d", addr, n, addr.IP, addr.Port)
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
