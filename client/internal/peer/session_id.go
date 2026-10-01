package peer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const sessionIDSize = 5

type ICESessionID string

// NewICESessionID generates a new session ID for distinguishing sessions
func NewICESessionID() (ICESessionID, error) {
	b := make([]byte, sessionIDSize)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return ICESessionID(hex.EncodeToString(b)), nil
}

func ICESessionIDFromBytes(b []byte) (ICESessionID, error) {
	if len(b) != sessionIDSize {
		return "", fmt.Errorf("invalid session ID length: %d", len(b))
	}
	return ICESessionID(hex.EncodeToString(b)), nil
}

// Bytes returns the raw bytes of the session ID for protobuf serialization
func (id ICESessionID) Bytes() ([]byte, error) {
	if len(id) == 0 {
		return nil, fmt.Errorf("ICE session ID is empty")
	}
	b, err := hex.DecodeString(string(id))
	if err != nil {
		return nil, fmt.Errorf("invalid ICE session ID encoding: %w", err)
	}
	if len(b) != sessionIDSize {
		return nil, fmt.Errorf("invalid ICE session ID length: expected %d bytes, got %d", sessionIDSize, len(b))
	}
	return b, nil
}

func (id ICESessionID) String() string {
	return string(id)
}
