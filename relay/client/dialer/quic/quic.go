package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

const (
	dialTimeout = 30 * time.Second
)

func Dial(address string) (net.Conn, error) {
	quicURL, err := prepareURL(address)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,                      // Set to true only for testing
		NextProtos:         []string{"netbird-relay"}, // Ensure this matches the server's ALPN
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
		EnableDatagrams: true,
	}

	// todo add support for custom dialer

	session, err := quic.DialAddr(ctx, quicURL, tlsConf, quicConfig)
	if err != nil {
		log.Errorf("failed to dial to Relay server via QUIC '%s': %s", quicURL, err)
		return nil, err
	}

	conn := NewConn(session, address)
	return conn, nil
}

func prepareURL(address string) (string, error) {
	if !strings.HasPrefix(address, "rel://") && !strings.HasPrefix(address, "rels://") {
		return "", fmt.Errorf("unsupported scheme: %s", address)
	}

	if strings.HasPrefix(address, "rels://") {
		return address[7:], nil
	}
	return address[6:], nil
}
