package relay

const (
	// WebSocketURLPath is the path for the websocket relay connection
	WebSocketURLPath = "/relay"

	// QUICInitialPacketSize is the conservative initial QUIC packet size (bytes)
	// for unknown-path PMTU, per RFC 9000 §14: 1280 (IPv6 min MTU) − 40 (IPv6
	// header) − 8 (UDP header) = 1232. DPLPMTUD may probe larger sizes later.
	QUICInitialPacketSize = 1232

	// QUICMaxDatagramSize is the largest message a QUIC datagram carries in a QUICInitialPacketSize packet.
	QUICMaxDatagramSize = QUICInitialPacketSize - quicShortHeaderTypeSize - quicMaxConnectionIDSize - quicAEADTagSize

	quicShortHeaderTypeSize = 1
	quicMaxConnectionIDSize = 20
	quicAEADTagSize         = 16
)
