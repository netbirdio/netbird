package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
)

type socket struct {
	LocalAddr net.Addr

	udpConn  *net.UDPConn
	listener *quic.Listener

	mu       sync.Mutex
	sessions int
	closing  bool
}

func newSocket(address string, tlsCfg *tls.Config, quicCfg *quic.Config, shared bool) (*socket, error) {
	udpConn, err := listenUDP(address, shared)
	if err != nil {
		return nil, err
	}

	listener, err := quic.Listen(udpConn, tlsCfg, quicCfg)
	if err != nil {
		if closeErr := udpConn.Close(); closeErr != nil {
			log.Debugf("failed to close QUIC socket: %v", closeErr)
		}
		return nil, err
	}

	return &socket{
		LocalAddr: udpConn.LocalAddr(),
		udpConn:   udpConn,
		listener:  listener,
	}, nil
}

func (s *socket) Serve(acceptFn func(conn relaylistener.Conn)) {
	for {
		session, err := s.listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				return
			}

			log.Errorf("Failed to accept QUIC session: %v", err)
			continue
		}

		log.Infof("QUIC client connected from: %s", session.RemoteAddr())
		s.track(session)
		conn := NewConn(session)
		// Run the accept handler (which performs the pre-auth handshake) in its
		// own goroutine so a slow or stalled handshake cannot block accepting
		// further connections.
		go acceptFn(conn)
	}
}

func (s *socket) Close() error {
	err := s.listener.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closing {
		return err
	}
	s.closing = true
	if s.sessions == 0 {
		s.closeUDPConn()
	}
	return err
}

func (s *socket) track(session *quic.Conn) {
	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()

	context.AfterFunc(session.Context(), s.release)
}

func (s *socket) release() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions--
	if s.closing && s.sessions == 0 {
		s.closeUDPConn()
	}
}

func (s *socket) closeUDPConn() {
	if err := s.udpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Debugf("failed to close QUIC socket: %v", err)
	}
}
