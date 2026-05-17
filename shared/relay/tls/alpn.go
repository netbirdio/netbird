package tls

const (
	// NBalpn is the ALPN identifier for the raw QUIC relay transport.
	NBalpn = "nb-quic"
	// H3alpn is the ALPN identifier for HTTP/3, which carries WebTransport
	// upgrades. Both ALPNs are offered on the same UDP socket so that 443/udp
	// can serve raw QUIC clients and WebTransport (browser) clients side by side.
	H3alpn = "h3"
)
