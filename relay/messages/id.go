package messages

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	prefixLength = 4
	IDSize       = sha256.Size + 4 // 4 is equal with len(prefix)
)

var (
	prefix = []byte("sha-") // 4 bytes
)

func HashID(peerID string) ([]byte, string) {
	idHash := sha256.Sum256([]byte(peerID))
	idHashString := string(prefix) + base64.StdEncoding.EncodeToString(idHash[:])
	prefixedHash := append(prefix, idHash[:]...)
	return prefixedHash, idHashString
}

func HashIDToString(idHash []byte) string {
	return fmt.Sprintf("%s%s", idHash[:prefixLength], base64.StdEncoding.EncodeToString(idHash[prefixLength:]))
}
