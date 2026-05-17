// Package quic implements the UDP listener for the relay server. It owns a
// single net.PacketConn and a quic.Transport, and demultiplexes incoming QUIC
// connections by negotiated ALPN:
//
//   - "nb-quic" -> raw QUIC relay transport (existing protocol)
//   - "h3"     -> HTTP/3, used by the WebTransport listener (optional)
//
// One UDP socket (typically 443/udp) carries both transports, so browsers
// using WebTransport and native clients using raw QUIC traverse the same
// firewall-friendly port.
package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"net/http"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/protocol"
	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
	nbRelay "github.com/netbirdio/netbird/shared/relay"
	relaytls "github.com/netbirdio/netbird/shared/relay/tls"
)

const Proto protocol.Protocol = "quic"

// H3Handler serves a single accepted QUIC connection that negotiated the "h3"
// ALPN. The WebTransport listener implements this by delegating to its
// embedded *http3.Server.ServeQUICConn.
type H3Handler interface {
	ServeQUICConn(conn *quic.Conn) error
}

// Listener owns the UDP socket and routes accepted QUIC connections by ALPN.
//
// If H3 is nil, only the raw QUIC ALPN is offered and the listener behaves
// exactly like the legacy single-ALPN listener. When H3 is set, both ALPNs
// are offered and h3 connections are handed off to H3.ServeQUICConn.
type Listener struct {
	Address   string
	TLSConfig *tls.Config

	// H3 is an optional HTTP/3 handler (typically a *http3.Server wrapped by
	// a webtransport.Server) that takes over connections negotiating the "h3"
	// ALPN. Set this before calling Listen.
	H3 H3Handler

	udpConn   *net.UDPConn
	transport *quic.Transport
	listener  *quic.Listener
}

func (l *Listener) Listen(acceptFn func(conn relaylistener.Conn)) error {
	udpAddr, err := net.ResolveUDPAddr("udp", l.Address)
	if err != nil {
		return fmt.Errorf("resolve UDP address %q: %w", l.Address, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP %q: %w", l.Address, err)
	}
	l.udpConn = udpConn
	l.transport = &quic.Transport{Conn: udpConn}

	tlsCfg := l.TLSConfig.Clone()
	if l.H3 != nil {
		tlsCfg.NextProtos = []string{relaytls.NBalpn, relaytls.H3alpn}
		log.Infof("QUIC listener on %s with HTTP/3 (WebTransport) ALPN mux", l.Address)
	} else {
		tlsCfg.NextProtos = []string{relaytls.NBalpn}
		log.Infof("QUIC listener on %s (raw QUIC only)", l.Address)
	}

	listener, err := l.transport.Listen(tlsCfg, &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: nbRelay.QUICInitialPacketSize,
	})
	if err != nil {
		return fmt.Errorf("create QUIC listener: %w", err)
	}
	l.listener = listener

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			log.Errorf("accept QUIC connection: %v", err)
			continue
		}
		go l.dispatch(conn, acceptFn)
	}
}

func (l *Listener) dispatch(conn *quic.Conn, acceptFn func(conn relaylistener.Conn)) {
	alpn := conn.ConnectionState().TLS.NegotiatedProtocol
	switch alpn {
	case relaytls.NBalpn:
		log.Infof("raw QUIC client connected from %s", conn.RemoteAddr())
		acceptFn(NewConn(conn))
	case relaytls.H3alpn:
		if l.H3 == nil {
			log.Warnf("h3 ALPN negotiated but no H3 handler installed; closing %s", conn.RemoteAddr())
			_ = conn.CloseWithError(0, "h3 unsupported")
			return
		}
		log.Debugf("h3/WebTransport client connected from %s", conn.RemoteAddr())
		if err := l.H3.ServeQUICConn(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Debugf("h3 connection from %s ended: %v", conn.RemoteAddr(), err)
		}
	default:
		log.Warnf("rejecting QUIC connection from %s: unexpected ALPN %q", conn.RemoteAddr(), alpn)
		_ = conn.CloseWithError(0, "unsupported alpn")
	}
}

func (l *Listener) Protocol() protocol.Protocol {
	return Proto
}

func (l *Listener) Shutdown(ctx context.Context) error {
	log.Infof("stopping QUIC listener")
	var firstErr error
	if l.listener != nil {
		if err := l.listener.Close(); err != nil {
			firstErr = fmt.Errorf("listener close: %w", err)
		}
	}
	if l.transport != nil {
		if err := l.transport.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("transport close: %w", err)
		}
	}
	if l.udpConn != nil {
		if err := l.udpConn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("udp close: %w", err)
		}
	}
	if firstErr != nil {
		return firstErr
	}
	log.Infof("QUIC listener stopped")
	return nil
}
