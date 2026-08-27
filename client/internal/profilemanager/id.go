package profilemanager

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// profileIDByteLen is the number of random bytes generated for a new
	// profile ID. The resulting hex string is twice this length.
	profileIDByteLen = 16

	// shortIDLen is the number of leading characters of an ID we render in
	// list output. Profiles per device are few, so 8 chars is collision-safe
	// in practice and easy to type as a prefix.
	shortIDLen = 8

	// maxProfileNameLen caps the human-readable profile name to keep table
	// output legible and prevent denial-of-service via huge JSON fields.
	maxProfileNameLen = 128

	// maxProfileIDLen bounds the on-disk filename we'll accept. New
	// IDs are 32 hex chars, legacy stems are sanitized profile names. The
	// cap is generous enough to cover both without permitting absurdly
	// long filenames.
	maxProfileIDLen = 64
)

type ID string

// generateProfileID returns a new random hex ID for a profile file.
func generateProfileID() (ID, error) {
	buf := make([]byte, profileIDByteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return ID(hex.EncodeToString(buf)), nil
}

// IsValidProfileFilenameStem reports whether id is safe to use as the stem
// of a profile JSON filename.
func IsValidProfileFilenameStem(id ID) bool {
	s := id.String()
	if s == "" || len(s) > maxProfileIDLen {
		return false
	}
	if s == defaultProfileName {
		return true
	}
	if strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") {
		return false
	}
	// filepath.Base catches any leftover separators on platforms with
	// exotic path conventions.
	if filepath.Base(s) != s {
		return false
	}
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// sanitizeDisplayName normalizes a user-supplied profile display name for
// storage. It strips ASCII control characters, rejects invalid UTF-8, and
// caps the length. Emojis, spaces, punctuation, and non-ASCII letters are
// preserved. Returns an error if nothing usable remains.
func sanitizeDisplayName(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("name is not valid UTF-8")
	}
	name = StripCtrlChars(name)
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name is empty after sanitization")
	}
	if utf8.RuneCountInString(name) > maxProfileNameLen {
		return "", fmt.Errorf("name exceeds %d characters", maxProfileNameLen)
	}
	return name, nil
}

// StripCtrlChars control characters from a name before printing it.
func StripCtrlChars(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		// Skip C0 controls and DEL, plus C1 controls (0x80–0x9F).
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ShortID truncates an ID for display.
func (id ID) ShortID() string {
	if id == DefaultProfileName {
		return DefaultProfileName
	}
	runes := []rune(id)
	if len(runes) <= shortIDLen {
		return id.String()
	}
	return string(runes[:shortIDLen])
}

func (id ID) String() string {
	return string(id)
}
