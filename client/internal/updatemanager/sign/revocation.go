package sign

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// RevocationList contains revoked Key IDs and their revocation timestamps
type RevocationList struct {
	Revoked map[KeyID]time.Time // KeyID -> revocation time
}

func (rl *RevocationList) MarshalJSON() ([]byte, error) {
	// Convert map[KeyID]time.Time to map[string]time.Time
	strMap := make(map[string]time.Time, len(rl.Revoked))
	for k, v := range rl.Revoked {
		strMap[k.String()] = v
	}

	return json.Marshal(map[string]interface{}{
		"revoked": strMap,
	})
}

func (rl *RevocationList) UnmarshalJSON(data []byte) error {
	var temp struct {
		Revoked map[string]time.Time `json:"revoked"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Convert map[string]time.Time back to map[KeyID]time.Time
	rl.Revoked = make(map[KeyID]time.Time, len(temp.Revoked))
	for k, v := range temp.Revoked {
		kid, err := ParseKeyID(k)
		if err != nil {
			return fmt.Errorf("failed to parse KeyID %q: %w", k, err)
		}
		rl.Revoked[kid] = v
	}

	return nil
}

func ParseRevocationList(data []byte) (*RevocationList, error) {
	var rl RevocationList
	if err := json.Unmarshal(data, &rl); err != nil {
		return nil, fmt.Errorf("failed to unmarshal revocation list: %w", err)
	}

	// Initialize the map if it's nil (in case of empty JSON object)
	if rl.Revoked == nil {
		rl.Revoked = make(map[KeyID]time.Time)
	}

	return &rl, nil
}

func CreateRevocationList(privateRootKey RootKey) ([]byte, []byte, error) {
	rl := RevocationList{
		Revoked: make(map[KeyID]time.Time),
	}

	signature, err := signRevocationList(privateRootKey, rl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign revocation list: %w", err)
	}

	rlData, err := json.Marshal(rl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal revocation list: %w", err)
	}

	signData, err := json.Marshal(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return rlData, signData, nil
}

func ExtendRevocationList(privateRootKey RootKey, rl RevocationList, kid KeyID) ([]byte, []byte, error) {
	rl.Revoked[kid] = time.Now().UTC()

	signature, err := signRevocationList(privateRootKey, rl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign revocation list: %w", err)
	}

	rlData, err := json.Marshal(rl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal revocation list: %w", err)
	}

	signData, err := json.Marshal(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return rlData, signData, nil
}

func signRevocationList(privateRootKey RootKey, rl RevocationList) (*Signature, error) {
	data, err := json.Marshal(rl)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal revocation list for signing: %w", err)
	}

	timestamp := time.Now().UTC()

	// This ensures the timestamp is cryptographically bound to the signature
	msg := make([]byte, 0, len(data)+8)
	msg = append(msg, data...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(timestamp.Unix()))

	sig := ed25519.Sign(privateRootKey.Key, msg)

	signature := &Signature{
		Signature: sig,
		Timestamp: time.Now().UTC(),
		KeyID:     privateRootKey.Metadata.ID,
		Algorithm: "ed25519",
		HashAlgo:  "sha512",
	}

	return signature, nil
}
