package udp

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

type Dialer struct {
}

func (d Dialer) Protocol() string {
	return "ebpfudp"
}

func (d Dialer) Dial(ctx context.Context, address string) (net.Conn, error) {
	// Parse the URL
	parsedURL, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address URL: %w", err)
	}

	// Extract host (e.g., "192.168.0.1:8080")
	host := parsedURL.Host
	if host == "" {
		return nil, fmt.Errorf("missing host in address")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}

	return net.DialUDP("udp", nil, udpAddr)
}
