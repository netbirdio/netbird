package reposign

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	maxRevocationSignatureAge       = 10 * 365 * 24 * time.Hour
	defaultRevocationListExpiration = 365 * 24 * time.Hour
)

type RevocationList struct {
	Revoked     map[KeyID]time.Time `json:"revoked"`      // KeyID -> revocation time
	LastUpdated time.Time           `json:"last_updated"` // When the list was last modified
	ExpiresAt   time.Time           `json:"expires_at"`   // When the list expires
}

func (rl RevocationList) MarshalJSON() ([]byte, error) {
	// Convert map[KeyID]time.Time to map[string]time.Time
	strMap := make(map[string]time.Time, len(rl.Revoked))
	for k, v := range rl.Revoked {
		strMap[k.String()] = v
	}

	return json.Marshal(map[string]interface{}{
		"revoked":      strMap,
		"last_updated": rl.LastUpdated,
		"expires_at":   rl.ExpiresAt,
	})
}

func (rl *RevocationList) UnmarshalJSON(data []byte) error {
	var temp struct {
		Revoked     map[string]time.Time `json:"revoked"`
		LastUpdated time.Time            `json:"last_updated"`
		ExpiresAt   time.Time            `json:"expires_at"`
		Version     int                  `json:"version"`
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

	rl.LastUpdated = temp.LastUpdated
	rl.ExpiresAt = temp.ExpiresAt

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

	if rl.LastUpdated.IsZero() {
		return nil, fmt.Errorf("revocation list missing last_updated timestamp")
	}

	if rl.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("revocation list missing expires_at timestamp")
	}

	return &rl, nil
}

func ValidateRevocationList(publicRootKeys []PublicKey, data []byte, signature Signature) (*RevocationList, error) {
	revoList, err := ParseRevocationList(data)
	if err != nil {
		log.Debugf("failed to parse revocation list: %s", err)
		return nil, err
	}

	now := time.Now().UTC()

	// Validate signature timestamp
	if signature.Timestamp.After(now.Add(maxClockSkew)) {
		err := fmt.Errorf("revocation signature timestamp is in the future: %v", signature.Timestamp)
		log.Debugf("revocation list signature error: %v", err)
		return nil, err
	}

	if now.Sub(signature.Timestamp) > maxRevocationSignatureAge {
		err := fmt.Errorf("revocation list signature is too old: %v (created %v)",
			now.Sub(signature.Timestamp), signature.Timestamp)
		log.Debugf("revocation list signature error: %v", err)
		return nil, err
	}

	// Ensure LastUpdated is not in the future (with clock skew tolerance)
	if revoList.LastUpdated.After(now.Add(maxClockSkew)) {
		err := fmt.Errorf("revocation list LastUpdated is in the future: %v", revoList.LastUpdated)
		log.Errorf("rejecting future-dated revocation list: %v", err)
		return nil, err
	}

	// Check if the revocation list has expired
	if now.After(revoList.ExpiresAt) {
		err := fmt.Errorf("revocation list expired at %v (current time: %v)", revoList.ExpiresAt, now)
		log.Errorf("rejecting expired revocation list: %v", err)
		return nil, err
	}

	// Ensure ExpiresAt is not in the future by more than the expected expiration window
	// (allows some clock skew but prevents maliciously long expiration times)
	if revoList.ExpiresAt.After(now.Add(maxRevocationSignatureAge)) {
		err := fmt.Errorf("revocation list ExpiresAt is too far in the future: %v", revoList.ExpiresAt)
		log.Errorf("rejecting revocation list with invalid expiration: %v", err)
		return nil, err
	}

	// Validate signature timestamp is close to LastUpdated
	// (prevents signing old lists with new timestamps)
	timeDiff := signature.Timestamp.Sub(revoList.LastUpdated).Abs()
	if timeDiff > maxClockSkew {
		err := fmt.Errorf("signature timestamp %v differs too much from list LastUpdated %v (diff: %v)",
			signature.Timestamp, revoList.LastUpdated, timeDiff)
		log.Errorf("timestamp mismatch in revocation list: %v", err)
		return nil, err
	}

	// Reconstruct the signed message: revocation_list_data || timestamp || version
	msg := make([]byte, 0, len(data)+8)
	msg = append(msg, data...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(signature.Timestamp.Unix()))

	if !verifyAny(publicRootKeys, msg, signature.Signature) {
		return nil, errors.New("revocation list verification failed")
	}
	return revoList, nil
}

func CreateRevocationList(privateRootKey RootKey, expiration time.Duration) ([]byte, []byte, error) {
	now := time.Now()
	rl := RevocationList{
		Revoked:     make(map[KeyID]time.Time),
		LastUpdated: now.UTC(),
		ExpiresAt:   now.Add(expiration).UTC(),
	}

	signature, err := signRevocationList(privateRootKey, rl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign revocation list: %w", err)
	}

	rlData, err := json.Marshal(&rl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal revocation list: %w", err)
	}

	signData, err := json.Marshal(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return rlData, signData, nil
}

func ExtendRevocationList(privateRootKey RootKey, rl RevocationList, kid KeyID, expiration time.Duration) ([]byte, []byte, error) {
	now := time.Now().UTC()

	rl.Revoked[kid] = now
	rl.LastUpdated = now
	rl.ExpiresAt = now.Add(expiration)

	signature, err := signRevocationList(privateRootKey, rl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign revocation list: %w", err)
	}

	rlData, err := json.Marshal(&rl)
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

	msg := make([]byte, 0, len(data)+8)
	msg = append(msg, data...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(timestamp.Unix()))

	sig := ed25519.Sign(privateRootKey.Key, msg)

	signature := &Signature{
		Signature: sig,
		Timestamp: timestamp,
		KeyID:     privateRootKey.Metadata.ID,
		Algorithm: "ed25519",
		HashAlgo:  "sha512",
	}

	return signature, nil
}
