package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

type Listener struct {
	// Address is the address to listen on
	Address string
	// TLSConfig is the TLS configuration for the server
	TLSConfig *tls.Config

	listener *quic.Listener
	acceptFn func(conn net.Conn)
}

func (l *Listener) Listen(acceptFn func(conn net.Conn)) error {
	l.acceptFn = acceptFn

	quicCfg := &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: 1452,
	}
	listener, err := quic.ListenAddr(l.Address, l.TLSConfig, quicCfg)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %v", err)
	}

	l.listener = listener
	log.Infof("QUIC server listening on address: %s", l.Address)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				return nil
			}

			log.Errorf("Failed to accept QUIC session: %v", err)
			continue
		}

		log.Infof("QUIC client connected from: %s", session.RemoteAddr())
		conn := NewConn(session)
		l.acceptFn(conn)
	}
}

func (l *Listener) Shutdown(ctx context.Context) error {
	if l.listener == nil {
		return nil
	}

	log.Infof("stopping QUIC listener")
	if err := l.listener.Close(); err != nil {
		return fmt.Errorf("listener shutdown failed: %v", err)
	}
	log.Infof("QUIC listener stopped")
	return nil
}
