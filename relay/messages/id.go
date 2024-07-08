package messages

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	prefixLength = 4
	IDSize       = prefixLength + sha256.Size
)

var (
	prefix = []byte("sha-") // 4 bytes
)

func HashID(peerID string) ([]byte, string) {
	idHash := sha256.Sum256([]byte(peerID))
	idHashString := string(prefix) + base64.StdEncoding.EncodeToString(idHash[:])
	var prefixedHash []byte
	prefixedHash = append(prefixedHash, prefix...)
	prefixedHash = append(prefixedHash, idHash[:]...)
	return prefixedHash, idHashString
}

func HashIDToString(idHash []byte) string {
	return fmt.Sprintf("%s%s", idHash[:prefixLength], base64.StdEncoding.EncodeToString(idHash[prefixLength:]))
}
