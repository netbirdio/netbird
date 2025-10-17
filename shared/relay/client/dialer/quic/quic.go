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

	quictls "github.com/netbirdio/netbird/shared/relay/tls"
	nbnet "github.com/netbirdio/netbird/client/net"
)

type Dialer struct {
}

func (d Dialer) Protocol() string {
	return Network
}

func (d Dialer) Dial(ctx context.Context, address string) (net.Conn, error) {
	quicURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	// Get the base TLS config
	tlsClientConfig := quictls.ClientQUICTLSConfig()

	// Set ServerName to hostname if not an IP address
	host, _, splitErr := net.SplitHostPort(quicURL)
	if splitErr == nil && net.ParseIP(host) == nil {
		// It's a hostname, not an IP - modify directly
		tlsClientConfig.ServerName = host
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod:   30 * time.Second,
		MaxIdleTimeout:    4 * time.Minute,
		EnableDatagrams:   true,
		InitialPacketSize: 1452,
	}

	udpConn, err := nbnet.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Errorf("failed to listen on UDP: %s", err)
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", quicURL)
	if err != nil {
		log.Errorf("failed to resolve UDP address: %s", err)
		return nil, err
	}

	session, err := quic.Dial(ctx, udpConn, udpAddr, tlsClientConfig, quicConfig)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		log.Errorf("failed to dial to Relay server via QUIC '%s': %s", quicURL, err)
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
			return host + ":" + defaultPort, nil
		}

		// return any other split error as is
		return "", err
	}

	return finalHost + ":" + finalPort, nil
}
