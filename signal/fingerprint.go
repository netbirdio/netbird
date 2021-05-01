package signal

import (
	"crypto/sha256"
	"encoding/hex"
)

const (
	HexTable = "0123456789abcdef"
)

// Generates a SHA256 Fingerprint of the string
func FingerPrint(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	sha := hasher.Sum(nil)
	return hex.EncodeToString(sha)
}
