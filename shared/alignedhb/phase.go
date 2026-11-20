package alignedhb

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// phaseLabel separates the aligned heartbeat phase hash from any other
// SHA-256 use of a peer id.
const phaseLabel = "netbird-aligned-heartbeat-phase-v1"

// Phase returns the offset inside period at which heartbeats for peer are
// sent: the first 8 bytes, big endian, of SHA-256(phaseLabel || peerID),
// modulo the period in milliseconds.
//
// peerID is messages.HashID of the WireGuard public key string, the only form
// the relay knows, so Management, Signal, relay and the client all derive the
// same phase from the identity they already have. There is no key and no day:
// the phase is fixed per peer key. A period below one millisecond has phase 0.
func Phase(peerID messages.PeerID, period time.Duration) time.Duration {
	p := period.Milliseconds()
	if p < 1 {
		return 0
	}
	h := sha256.New()
	h.Write([]byte(phaseLabel))
	h.Write(peerID[:])
	sum := h.Sum(nil)
	n := binary.BigEndian.Uint64(sum[:8])
	return time.Duration(n%uint64(p)) * time.Millisecond
}
