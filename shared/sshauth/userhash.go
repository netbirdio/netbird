package sshauth

import (
	"encoding/hex"

	"golang.org/x/crypto/blake2b"
)

// UserIDHash represents a hashed user ID (BLAKE2b-256)
type UserIDHash [32]byte

// HashUserID hashes a user ID using BLAKE2b-256 and returns the hash value
// This function must produce the same hash on both client and management server
func HashUserID(userID string) (UserIDHash, error) {
	return blake2b.Sum256([]byte(userID)), nil
}

// String returns the hexadecimal string representation of the hash
func (h UserIDHash) String() string {
	return hex.EncodeToString(h[:])
}
