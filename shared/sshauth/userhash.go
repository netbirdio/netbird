package sshauth

import (
	"fmt"
	"hash/fnv"
)

// UserIDHash represents a hashed user ID (FNV-1a 64-bit)
type UserIDHash uint64

// HashUserID hashes a user ID using FNV-1a (64-bit) and returns the hash value
// This function must produce the same hash on both client and management server
func HashUserID(userID string) (UserIDHash, error) {
	h := fnv.New64a()
	if _, err := h.Write([]byte(userID)); err != nil {
		return 0, fmt.Errorf("hash user ID: %w", err)
	}
	return UserIDHash(h.Sum64()), nil
}

// String returns the hexadecimal string representation of the hash
func (h UserIDHash) String() string {
	return fmt.Sprintf("%016x", uint64(h))
}
