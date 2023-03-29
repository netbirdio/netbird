package server

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"hash/crc32"
	"time"

	"codeberg.org/ac/base62"
	b "github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/rs/xid"
)

const (
	// PATPrefix is the globally used, 4 char prefix for personal access tokens
	PATPrefix = "nbp_"
	// PATSecretLength number of characters used for the secret inside the token
	PATSecretLength = 30
	// PATChecksumLength number of characters used for the encoded checksum of the secret inside the token
	PATChecksumLength = 6
	// PATLength total number of characters used for the token
	PATLength = 40
)

// PersonalAccessToken holds all information about a PAT including a hashed version of it for verification
type PersonalAccessToken struct {
	ID             string
	Name           string
	HashedToken    string
	ExpirationDate time.Time
	// scope could be added in future
	CreatedBy string
	CreatedAt time.Time
	LastUsed  time.Time
}

// PersonalAccessTokenGenerated holds the new PersonalAccessToken and the plain text version of it
type PersonalAccessTokenGenerated struct {
	PlainToken string
	PersonalAccessToken
}

// CreateNewPAT will generate a new PersonalAccessToken that can be assigned to a User.
// Additionally, it will return the token in plain text once, to give to the user and only save a hashed version
func CreateNewPAT(name string, expirationInDays int, createdBy string) (*PersonalAccessTokenGenerated, error) {
	hashedToken, plainToken, err := generateNewToken()
	if err != nil {
		return nil, err
	}
	currentTime := time.Now().UTC()
	return &PersonalAccessTokenGenerated{
		PersonalAccessToken: PersonalAccessToken{
			ID:             xid.New().String(),
			Name:           name,
			HashedToken:    hashedToken,
			ExpirationDate: currentTime.AddDate(0, 0, expirationInDays),
			CreatedBy:      createdBy,
			CreatedAt:      currentTime,
			LastUsed:       currentTime,
		},
		PlainToken: plainToken,
	}, nil

}

func generateNewToken() (string, string, error) {
	secret, err := b.Random(PATSecretLength)
	if err != nil {
		return "", "", err
	}

	checksum := crc32.ChecksumIEEE([]byte(secret))
	encodedChecksum := base62.Encode(checksum)
	paddedChecksum := fmt.Sprintf("%06s", encodedChecksum)
	plainToken := PATPrefix + secret + paddedChecksum
	hashedToken := sha256.Sum256([]byte(plainToken))
	encodedHashedToken := b64.StdEncoding.EncodeToString(hashedToken[:])
	return encodedHashedToken, plainToken, nil
}
