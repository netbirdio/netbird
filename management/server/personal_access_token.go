package server

import (
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"math/rand"
	"time"

	"codeberg.org/ac/base62"
)

type PersonalAccessToken struct {
	Description    string
	HashedToken    [32]byte
	ExpirationDate time.Time
	// scope could be added in future
	CreatedBy User // should we add that?
	CreatedAt time.Time
	LastUsed  time.Time
}

const (
	// IEEE is by far and away the most common CRC-32 polynomial.
	// Used by ethernet (IEEE 802.3), v.42, fddi, gzip, zip, png, ...
	IEEE = 0xedb88320
	// Castagnoli polynomial, used in iSCSI.
	// Has better error detection characteristics than IEEE.
	// https://dx.doi.org/10.1109/26.231911
	Castagnoli = 0x82f63b78
	// Koopman polynomial.
	// Also has better error detection characteristics than IEEE.
	// https://dx.doi.org/10.1109/DSN.2002.1028931
	Koopman = 0xeb31d82e
)

func CreateNewPAT(description string, expirationInDays int, createdBy User) (*PersonalAccessToken, string) {
	hashedToken, plainToken := generateNewToken()
	currentTime := time.Now().UTC()
	return &PersonalAccessToken{
		Description:    description,
		HashedToken:    hashedToken,
		ExpirationDate: currentTime.AddDate(0, 0, expirationInDays),
		CreatedBy:      createdBy,
		CreatedAt:      currentTime,
		LastUsed:       currentTime, // using creation time as nil not possible
	}, plainToken
}

func generateNewToken() ([32]byte, string) {
	token := randStringRunes(30)

	crc32q := crc32.MakeTable(IEEE)
	checksum := crc32.Checksum([]byte(token), crc32q)
	encodedChecksum := base62.Encode(checksum)
	paddedChecksum := fmt.Sprintf("%06s", encodedChecksum)
	plainToken := "nbp_" + token + paddedChecksum
	hashedToken := sha256.Sum256([]byte(plainToken))
	return hashedToken, plainToken
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
