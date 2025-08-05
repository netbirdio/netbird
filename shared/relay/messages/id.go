package messages

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	prefixLength = 4
	peerIDSize   = prefixLength + sha256.Size
)

var (
	prefix = []byte("sha-") // 4 bytes
)

type PeerID [peerIDSize]byte

func (p PeerID) String() string {
	return fmt.Sprintf("%s%s", p[:prefixLength], base64.StdEncoding.EncodeToString(p[prefixLength:]))
}

// HashID generates a sha256 hash from the peerID and returns the hash and the human-readable string
func HashID(peerID string) PeerID {
	idHash := sha256.Sum256([]byte(peerID))
	var prefixedHash [peerIDSize]byte
	copy(prefixedHash[:prefixLength], prefix)
	copy(prefixedHash[prefixLength:], idHash[:])
	return prefixedHash
}
