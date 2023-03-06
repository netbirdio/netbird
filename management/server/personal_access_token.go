package server

import (
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"math/rand"
	"time"

	"codeberg.org/ac/base62"
	"github.com/rs/xid"
)

type PersonalAccessToken struct {
	ID             string
	Description    string
	HashedToken    [32]byte
	ExpirationDate time.Time
	// scope could be added in future
	CreatedBy string
	CreatedAt time.Time
	LastUsed  time.Time
}

func CreateNewPAT(description string, expirationInDays int, createdBy string) (*PersonalAccessToken, string) {
	hashedToken, plainToken := generateNewToken()
	currentTime := time.Now().UTC()
	return &PersonalAccessToken{
		ID:             xid.New().String(),
		Description:    description,
		HashedToken:    hashedToken,
		ExpirationDate: currentTime.AddDate(0, 0, expirationInDays),
		CreatedBy:      createdBy,
		CreatedAt:      currentTime,
		LastUsed:       currentTime,
	}, plainToken
}

func generateNewToken() ([32]byte, string) {
	token := randStringRunes(30)

	checksum := crc32.ChecksumIEEE([]byte(token))
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
