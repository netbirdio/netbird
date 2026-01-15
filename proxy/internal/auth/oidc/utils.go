package oidc

import (
	"crypto/rand"
	"encoding/base64"
)

// generateRandomString generates a cryptographically secure random string of the specified length
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
