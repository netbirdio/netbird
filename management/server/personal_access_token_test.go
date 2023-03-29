package server

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"hash/crc32"
	"strings"
	"testing"

	"codeberg.org/ac/base62"
	"github.com/stretchr/testify/assert"
)

func TestPAT_GenerateToken_Hashing(t *testing.T) {
	hashedToken, plainToken, _ := generateNewToken()
	expectedToken := sha256.Sum256([]byte(plainToken))
	encodedExpectedToken := b64.StdEncoding.EncodeToString(expectedToken[:])
	assert.Equal(t, hashedToken, encodedExpectedToken)
}

func TestPAT_GenerateToken_Prefix(t *testing.T) {
	_, plainToken, _ := generateNewToken()
	fourCharPrefix := plainToken[:4]
	assert.Equal(t, PATPrefix, fourCharPrefix)
}

func TestPAT_GenerateToken_Checksum(t *testing.T) {
	_, plainToken, _ := generateNewToken()
	tokenWithoutPrefix := strings.Split(plainToken, "_")[1]
	if len(tokenWithoutPrefix) != 36 {
		t.Fatal("Token has wrong length")
	}
	secret := tokenWithoutPrefix[:len(tokenWithoutPrefix)-6]
	tokenCheckSum := tokenWithoutPrefix[len(tokenWithoutPrefix)-6:]

	expectedChecksum := crc32.ChecksumIEEE([]byte(secret))
	actualChecksum, err := base62.Decode(tokenCheckSum)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedChecksum, actualChecksum)
}
