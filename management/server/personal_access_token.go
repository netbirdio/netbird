package server

import (
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"time"

	"codeberg.org/ac/base62"
	b "github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/rs/xid"
)

const (
	// PATPrefix is the globally used, 4 char prefix for personal access tokens
	PATPrefix    = "nbp_"
	secretLength = 30
	PATLength    = 40
)

// PersonalAccessToken holds all information about a PAT including a hashed version of it for verification
type PersonalAccessToken struct {
	ID             string
	Description    string
	HashedToken    string
	ExpirationDate time.Time
	// scope could be added in future
	CreatedBy string
	CreatedAt time.Time
	LastUsed  time.Time
}

// CreateNewPAT will generate a new PersonalAccessToken that can be assigned to a User.
// Additionally, it will return the token in plain text once, to give to the user and only save a hashed version
func CreateNewPAT(description string, expirationInDays int, createdBy string) (*PersonalAccessToken, string, error) {
	hashedToken, plainToken, err := generateNewToken()
	if err != nil {
		return nil, "", err
	}
	currentTime := time.Now().UTC()
	return &PersonalAccessToken{
		ID:             xid.New().String(),
		Description:    description,
		HashedToken:    hashedToken,
		ExpirationDate: currentTime.AddDate(0, 0, expirationInDays),
		CreatedBy:      createdBy,
		CreatedAt:      currentTime,
		LastUsed:       currentTime,
	}, plainToken, nil
}

func generateNewToken() (string, string, error) {
	secret, err := b.Random(secretLength)
	if err != nil {
		return "", "", err
	}

	checksum := crc32.ChecksumIEEE([]byte(secret))
	encodedChecksum := base62.Encode(checksum)
	paddedChecksum := fmt.Sprintf("%06s", encodedChecksum)
	plainToken := PATPrefix + secret + paddedChecksum
	hashedToken := sha256.Sum256([]byte(plainToken))
	return string(hashedToken[:]), plainToken, nil
}
