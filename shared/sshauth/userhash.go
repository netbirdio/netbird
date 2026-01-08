package sshauth

import (
	"encoding/hex"

	"golang.org/x/crypto/blake2b"
)

// UserIDHash represents a hashed user ID (BLAKE2b-128)
type UserIDHash [16]byte

// HashUserID hashes a user ID using BLAKE2b-128 and returns the hash value
// This function must produce the same hash on both client and management server
func HashUserID(userID string) (UserIDHash, error) {
	hash, err := blake2b.New(16, nil)
	if err != nil {
		return UserIDHash{}, err
	}
	hash.Write([]byte(userID))
	var result UserIDHash
	copy(result[:], hash.Sum(nil))
	return result, nil
}

// String returns the hexadecimal string representation of the hash
func (h UserIDHash) String() string {
	return hex.EncodeToString(h[:])
}
