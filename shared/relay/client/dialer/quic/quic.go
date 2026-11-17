package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/shared/alignedhb"
	nbRelay "github.com/netbirdio/netbird/shared/relay"
	quictls "github.com/netbirdio/netbird/shared/relay/tls"
)

const (
	// maxIdleTimeout stays above the receive timeout of the longest aligned
	// heartbeat period. quic-go uses the lower of both sides.
	maxIdleTimeout = alignedhb.MaxPeriod + alignedhb.ReceiveMargin
	// stockKeepAlivePeriod is the QUIC ping interval of clients without the
	// aligned heartbeat.
	stockKeepAlivePeriod = 30 * time.Second
)

// alignedHeartbeat reports whether this client asks for the aligned heartbeat.
// A var so tests can switch it.
var alignedHeartbeat = func() bool {
	_, ok := alignedhb.ClientPeriod()
	return ok
}

// keepAlivePeriod returns the QUIC ping interval. An aligned heartbeat client
// sends no pings: the relay health check keeps the connection alive, and a ping
// between two heartbeats would wake the radio. Other clients ping as before.
func keepAlivePeriod() time.Duration {
	if alignedHeartbeat() {
		return 0
	}
	return stockKeepAlivePeriod
}

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
		KeepAlivePeriod:   keepAlivePeriod(),
		MaxIdleTimeout:    maxIdleTimeout,
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
