// Package stun provides an embedded STUN server for NAT traversal discovery.
package stun

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/go-multierror"
	nberrors "github.com/netbirdio/netbird/client/errors"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/formatter"
	"github.com/pion/stun/v3"
)

// ErrServerClosed is returned by Listen when the server is shut down gracefully.
var ErrServerClosed = errors.New("stun: server closed")

// ErrNoListeners is returned by Listen when no UDP connections were provided.
var ErrNoListeners = errors.New("stun: no listeners configured")

// Server implements a STUN server that responds to binding requests
// with the client's reflexive transport address.
type Server struct {
	conns    []*net.UDPConn
	logger   *log.Entry
	logLevel log.Level

	wg sync.WaitGroup
}

// NewServer creates a new STUN server with the given UDP listeners.
// The caller is responsible for creating and providing the listeners.
// logLevel can be: panic, fatal, error, warn, info, debug, trace
func NewServer(conns []*net.UDPConn, logLevel string) *Server {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.InfoLevel
	}

	// Create a separate logger with its own level setting
	// This allows --stun-log-level to work independently of --log-level
	stunLogger := log.New()
	stunLogger.SetOutput(log.StandardLogger().Out)
	stunLogger.SetLevel(level)
	// Use the formatter package to set up formatter, ReportCaller, and context hook
	formatter.SetTextFormatter(stunLogger)

	logger := stunLogger.WithField("component", "stun")
	logger.Infof("STUN server log level set to: %s", level.String())

	return &Server{
		conns:    conns,
		logger:   logger,
		logLevel: level,
	}
}

// Listen starts the STUN server and blocks until the server is shut down.
// Returns ErrServerClosed when shut down gracefully via Shutdown.
// Returns ErrNoListeners if no UDP connections were provided.
func (s *Server) Listen() error {
	if len(s.conns) == 0 {
		return ErrNoListeners
	}

	// Start a read loop for each listener
	for _, conn := range s.conns {
		s.logger.Infof("STUN server listening on %s", conn.LocalAddr())
		s.wg.Add(1)
		go s.readLoop(conn)
	}

	s.wg.Wait()
	return ErrServerClosed
}

// readLoop continuously reads UDP packets and handles STUN requests.
func (s *Server) readLoop(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 1500) // Standard MTU size
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)

		if err != nil {
			// Check if the connection was closed externally
			if errors.Is(err, net.ErrClosed) {
				s.logger.Info("UDP connection closed, stopping read loop")
				return
			}
			s.logger.Warnf("failed to read UDP packet: %v", err)
			continue
		}

		// Handle packet in the same goroutine to avoid complexity
		// STUN responses are small and fast
		s.handlePacket(conn, buf[:n], remoteAddr)
	}
}

// handlePacket processes a STUN request and sends a response.
func (s *Server) handlePacket(conn *net.UDPConn, data []byte, addr *net.UDPAddr) {
	localPort := conn.LocalAddr().(*net.UDPAddr).Port

	s.logger.Debugf("[port:%d] received %d bytes from %s", localPort, len(data), addr)

	// Check if it's a STUN message
	if !stun.IsMessage(data) {
		s.logger.Debugf("[port:%d] not a STUN message (first bytes: %x)", localPort, data[:min(len(data), 8)])
		return
	}

	// Parse the STUN message
	msg := &stun.Message{Raw: data}
	if err := msg.Decode(); err != nil {
		s.logger.Warnf("[port:%d] failed to decode STUN message from %s: %v", localPort, addr, err)
		return
	}

	s.logger.Debugf("[port:%d] received STUN %s from %s (tx=%x)", localPort, msg.Type, addr, msg.TransactionID[:8])

	// Only handle binding requests
	if msg.Type != stun.BindingRequest {
		s.logger.Debugf("[port:%d] ignoring non-binding request: %s", localPort, msg.Type)
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
		s.logger.Errorf("[port:%d] failed to build STUN response: %v", localPort, err)
		return
	}

	// Send the response on the same connection it was received on
	n, err := conn.WriteToUDP(response.Raw, addr)
	if err != nil {
		s.logger.Errorf("[port:%d] failed to send STUN response to %s: %v", localPort, addr, err)
		return
	}

	s.logger.Debugf("[port:%d] sent STUN BindingSuccess to %s (%d bytes) with XORMappedAddress %s:%d", localPort, addr, n, addr.IP, addr.Port)
}

// Shutdown gracefully stops the STUN server.
func (s *Server) Shutdown() error {
	s.logger.Info("shutting down STUN server")

	var merr *multierror.Error

	for _, conn := range s.conns {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			merr = multierror.Append(merr, fmt.Errorf("close STUN UDP connection: %w", err))
		}
	}

	// Wait for all readLoops to finish
	s.wg.Wait()
	return nberrors.FormatErrorOrNil(merr)
}
