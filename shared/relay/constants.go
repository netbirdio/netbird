package relay

const (
	// WebSocketURLPath is the path for the websocket relay connection
	WebSocketURLPath = "/relay"

	// QUICInitialPacketSize is the conservative initial QUIC packet size (bytes)
	// for unknown-path PMTU, per RFC 9000 §14: 1280 (IPv6 min MTU) − 40 (IPv6
	// header) − 8 (UDP header) = 1232. DPLPMTUD may probe larger sizes later.
	QUICInitialPacketSize = 1232

	// QUICMaxDatagramSize is the largest message that fits a QUIC datagram in a
	// QUICInitialPacketSize packet with every header field at its longest, per
	// RFC 9000 §17.3.1 and RFC 9221 §4: 1232 − 1 (short header type byte) − 20
	// (connection ID) − 4 (packet number) − 3 (DATAGRAM frame type and length) − 16
	// (AEAD tag) = 1188.
	QUICMaxDatagramSize = QUICInitialPacketSize - quicShortHeaderTypeSize - quicMaxConnectionIDSize -
		quicMaxPacketNumberSize - quicDatagramFrameHeaderSize - quicAEADTagSize

	quicShortHeaderTypeSize     = 1
	quicMaxConnectionIDSize     = 20
	quicMaxPacketNumberSize     = 4
	quicDatagramFrameHeaderSize = 3
	quicAEADTagSize             = 16
)
