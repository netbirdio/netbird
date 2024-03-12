package healthcheck

import "encoding/binary"

const (
	// magicCookie is fixed value that aids in distinguishing health check packets
	// from packets of other protocols when health check is multiplexed with those
	// other protocols on the same Port.
	//
	// The magic cookie field MUST contain the fixed value 0x2112A442 in
	// network byte order.
	//
	// Defined in "STUN Message Structure", section 6.
	magicCookie         = 0x2112A442
	attributeHeaderSize = 4
	messageHeaderSize   = 20
)

// IsMessage returns true if b looks like STUN message.
// Useful for multiplexing. IsMessage does not guarantee
// that decoding will be successful.
func IsMessage(b []byte) bool {
	return len(b) >= messageHeaderSize && binary.BigEndian.Uint32(b[4:8]) == magicCookie && b[9] == 0x00
}
