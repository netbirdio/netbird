package relay

const (
	// WebSocketURLPath is the path for the websocket relay connection
	WebSocketURLPath = "/relay"

	// QUICInitialPacketSize is the initial QUIC packet size in bytes.
	// 1280 is the IPv6 minimum MTU (RFC 2460) and is safe across encapsulated
	// networks (VXLAN, WireGuard, GRE, etc.) where the effective MTU may be
	// significantly smaller than the physical 1500-byte Ethernet MTU.
	QUICInitialPacketSize = 1280
)
