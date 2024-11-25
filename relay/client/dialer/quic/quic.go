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

	nbnet "github.com/netbirdio/netbird/util/net"
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

	session, err := quic.Dial(ctx, udpConn, udpAddr, tlsConf, quicConfig)
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
