package pqkem

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// dataPathMACLabel separates the data-path MAC key from the PSK the consumer programs
// into its channel, so the same secret never serves two purposes directly.
const dataPathMACLabel = "netbird-pq-datapath-mac-v1"

// dataPathTagSize is the length of the HMAC-SHA256 tag appended to every data-path frame.
const dataPathTagSize = sha256.Size

// dataPathMACKey derives the key that authenticates data-path messages from a PSK both
// peers hold.
func dataPathMACKey(psk PSK) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, psk[:], nil, dataPathMACLabel, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("derive data-path mac key: %w", err)
	}
	return key, nil
}

// sealDataPath appends the frame's HMAC-SHA256 tag under key.
func sealDataPath(key, frame []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(frame)
	sealed := make([]byte, 0, len(frame)+dataPathTagSize)
	sealed = append(sealed, frame...)
	return mac.Sum(sealed)
}

// openDataPath verifies a sealed frame under key and returns the frame without its tag.
func openDataPath(key, sealed []byte) ([]byte, bool) {
	if len(sealed) < dataPathTagSize {
		return nil, false
	}
	frame, tag := sealed[:len(sealed)-dataPathTagSize], sealed[len(sealed)-dataPathTagSize:]
	mac := hmac.New(sha256.New, key)
	mac.Write(frame)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, false
	}
	return frame, true
}
