package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
	nbRelay "github.com/netbirdio/netbird/shared/relay"
	quictls "github.com/netbirdio/netbird/shared/relay/tls"
)

type Dialer struct {
}

func (d Dialer) Protocol() string {
	return Network
}

// DatagramSized marks QUIC as a datagram-sized transport: relay traffic is
// carried in QUIC DATAGRAM frames, which must fit a single packet.
func (d Dialer) DatagramSized() {
	// Intentional marker method; presence is the capability signal.
}

func (d Dialer) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	quicURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	// Get the base TLS config
	tlsClientConfig := quictls.ClientQUICTLSConfig()

	switch {
	case serverName != "" && net.ParseIP(serverName) == nil:
		tlsClientConfig.ServerName = serverName
	default:
		host, _, splitErr := net.SplitHostPort(quicURL)
		if splitErr == nil && net.ParseIP(host) == nil {
			tlsClientConfig.ServerName = host
		}
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod:   30 * time.Second,
		MaxIdleTimeout:    4 * time.Minute,
		EnableDatagrams:   true,
		InitialPacketSize: nbRelay.QUICInitialPacketSize,
		Tracer:            connectionTracer(quicURL),
	}

	udpConn, err := nbnet.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", quicURL)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", quicURL, err)
	}

	session, err := quic.Dial(ctx, udpConn, udpAddr, tlsClientConfig, quicConfig)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		log.Debugf("failed to dial to Relay server via QUIC '%s': %s", quicURL, err)
		return nil, err
	}

	conn := NewConn(session)
	return conn, nil
}

// logSink implements both qlogwriter.Trace and qlogwriter.Recorder, forwarding
// the few qlog events the relay client cares about to logrus instead of
// writing a qlog file. It holds no mutable state and logrus entries are safe
// to share, so one value can serve every producer on the connection.
type logSink struct {
	log *log.Entry
}

func (s logSink) AddProducer() qlogwriter.Recorder { return s }

func (s logSink) SupportsSchemas(schema string) bool { return schema == qlog.EventSchema }

func (s logSink) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case qlog.MTUUpdated:
		if e.Done {
			s.log.Infof("QUIC path MTU settled at %d", e.Value)
			return
		}
		s.log.Debugf("QUIC path MTU probing at %d", e.Value)
	case qlog.ConnectionClosed:
		s.log.Debugf("QUIC connection closed: %s", closeReason(e))
	}
}

func (s logSink) Close() error { return nil }

// connectionTracer returns a QUIC tracer that logs the DPLPMTUD result and the
// reason a relay connection closed, so the path MTU settled on and teardown
// cause are visible in logs. Lines carry the relay address as a structured
// field, matching the rest of the relay client logging.
func connectionTracer(addr string) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	relayLog := log.WithField("relay", addr)
	return func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return logSink{log: relayLog}
	}
}

// closeReason renders a ConnectionClosed event as a single line. The event
// carries the error as separate initiator, code, trigger and reason fields,
// any of which may be unset.
func closeReason(e qlog.ConnectionClosed) string {
	parts := []string{fmt.Sprintf("closed by %s", e.Initiator)}
	switch {
	case e.ConnectionError != nil:
		parts = append(parts, fmt.Sprintf("transport error: %s", *e.ConnectionError))
	case e.ApplicationError != nil:
		parts = append(parts, fmt.Sprintf("application error: %d", *e.ApplicationError))
	}
	if e.Trigger != "" {
		parts = append(parts, fmt.Sprintf("trigger: %s", e.Trigger))
	}
	if e.Reason != "" {
		parts = append(parts, fmt.Sprintf("reason: %s", e.Reason))
	}
	return strings.Join(parts, ", ")
}

func prepareURL(address string) (string, error) {
	var host string
	var defaultPort string

	switch {
	case strings.HasPrefix(address, "rels://"):
		host = address[7:]
		defaultPort = "443"
	case strings.HasPrefix(address, "rel://"):
		host = address[6:]
		defaultPort = "80"
	default:
		return "", fmt.Errorf("unsupported scheme: %s", address)
	}

	finalHost, finalPort, err := net.SplitHostPort(host)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return net.JoinHostPort(strings.Trim(host, "[]"), defaultPort), nil
		}

		// return any other split error as is
		return "", err
	}

	return net.JoinHostPort(finalHost, finalPort), nil
}
