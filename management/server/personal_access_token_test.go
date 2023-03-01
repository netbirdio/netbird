package server

import (
	"crypto/sha256"
	"hash/crc32"
	"strings"
	"testing"

	"codeberg.org/ac/base62"
	"github.com/stretchr/testify/assert"
)

func TestPAT_GenerateToken_Hashing(t *testing.T) {
	hashedToken, plainToken := generateNewToken()

	assert.Equal(t, hashedToken, sha256.Sum256([]byte(plainToken)))
}

func TestPAT_GenerateToken_Prefix(t *testing.T) {
	_, plainToken := generateNewToken()
	fourLetterPrefix := plainToken[:4] // should be 3
	assert.Equal(t, "nbp_", fourLetterPrefix)
}

func TestPAT_GenerateToken_Checksum(t *testing.T) {
	_, plainToken := generateNewToken()
	tokenWithoutPrefix := strings.Split(plainToken, "_")[1]
	if len(tokenWithoutPrefix) != 36 {
		t.Fatal("Token has wrong length")
	}
	token := tokenWithoutPrefix[:len(tokenWithoutPrefix)-6]
	tokenCheckSum := tokenWithoutPrefix[len(tokenWithoutPrefix)-6:]

	crc32q := crc32.MakeTable(IEEE)
	expectedChecksum := crc32.Checksum([]byte(token), crc32q)
	actualChecksum, err := base62.Decode(tokenCheckSum)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedChecksum, actualChecksum)
}
