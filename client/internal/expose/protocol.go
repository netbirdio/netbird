package expose

import (
	"fmt"
	"strings"
)

// ProtocolType represents the protocol used for exposing a service.
type ProtocolType int

const (
	// ProtocolHTTP exposes the service as HTTP.
	ProtocolHTTP ProtocolType = 0
	// ProtocolHTTPS exposes the service as HTTPS.
	ProtocolHTTPS ProtocolType = 1
	// ProtocolTCP exposes the service as TCP.
	ProtocolTCP ProtocolType = 2
	// ProtocolUDP exposes the service as UDP.
	ProtocolUDP ProtocolType = 3
	// ProtocolTLS exposes the service as TLS.
	ProtocolTLS ProtocolType = 4
)

// ParseProtocolType parses a protocol string into a ProtocolType.
func ParseProtocolType(s string) (ProtocolType, error) {
	switch strings.ToLower(s) {
	case "http":
		return ProtocolHTTP, nil
	case "https":
		return ProtocolHTTPS, nil
	case "tcp":
		return ProtocolTCP, nil
	case "udp":
		return ProtocolUDP, nil
	case "tls":
		return ProtocolTLS, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q: must be http, https, tcp, udp, or tls", s)
	}
}
