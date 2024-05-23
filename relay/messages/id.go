package messages

import (
	"crypto/sha256"
	"encoding/base64"
)

const (
	IDSize = sha256.Size
)

func HashID(peerID string) ([]byte, string) {
	idHash := sha256.Sum256([]byte(peerID))
	idHashString := base64.StdEncoding.EncodeToString(idHash[:])
	return idHash[:], idHashString
}

func HashIDToString(idHash []byte) string {
	return base64.StdEncoding.EncodeToString(idHash[:])
}
