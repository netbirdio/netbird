package dialer

import "net"

// DatagramSized is implemented by dialers whose connections carry each write in
// a single datagram, so a write can be rejected when it exceeds the path's
// datagram budget (e.g. QUIC). Transports without this capability (e.g.
// WebSocket over TCP) impose no per-write size limit, so the relay client can
// fall back to them when a datagram-sized transport rejects a write as too
// large. The capability is advertised per dialer rather than hardcoded, so a
// new transport only needs to declare whether it is datagram-sized.
type DatagramSized interface {
	DatagramSized()
}

// IsDatagramSized reports whether d produces datagram-sized connections.
func IsDatagramSized(d DialeFn) bool {
	_, ok := d.(DatagramSized)
	return ok
}

// IsConnDatagramSized reports whether conn carries each write in a single
// unreliable datagram, i.e. the transport provides no flow control or
// retransmission and overflows must be dropped rather than waited out.
func IsConnDatagramSized(conn net.Conn) bool {
	_, ok := conn.(DatagramSized)
	return ok
}
