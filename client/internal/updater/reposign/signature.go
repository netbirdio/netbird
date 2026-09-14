package reposign

import (
	"encoding/json"
	"time"
)

// Signature contains a signature with associated Metadata
type Signature struct {
	Signature []byte    `json:"signature"`
	Timestamp time.Time `json:"timestamp"`
	KeyID     KeyID     `json:"key_id"`
	Algorithm string    `json:"algorithm"` // "ed25519"
	HashAlgo  string    `json:"hash_algo"` // "blake2s" or sha512
}

func ParseSignature(data []byte) (*Signature, error) {
	var signature Signature
	if err := json.Unmarshal(data, &signature); err != nil {
		return nil, err
	}

	return &signature, nil
}
