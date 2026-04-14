package tpm

import (
	"fmt"
	"regexp"
)

// validKeyIDPattern matches safe key IDs: 1–64 alphanumeric chars, hyphens, and underscores.
// This prevents path traversal in cert file paths (e.g. "../../../etc/passwd") and
// Keychain label injection on macOS, which run as root or LocalSystem.
var validKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_]{1,64}$`)

// validateKeyID returns an error if keyID is not a safe identifier.
func validateKeyID(keyID string) error {
	if !validKeyIDPattern.MatchString(keyID) {
		return fmt.Errorf("tpm: invalid keyID %q: must match [a-zA-Z0-9\\-_]{1,64}", keyID)
	}
	return nil
}
