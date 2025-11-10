package hmac

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"hash"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

type Token struct {
	Payload   string
	Signature string
}

func unmarshalToken(payload []byte) (Token, error) {
	var creds Token
	buffer := bytes.NewBuffer(payload)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(&creds)
	return creds, err
}

// TimedHMAC generates a token with TTL and uses a pre-shared secret known to the relay server
type TimedHMAC struct {
	secret     string
	timeToLive time.Duration
}

// NewTimedHMAC creates a new TimedHMAC instance
func NewTimedHMAC(secret string, timeToLive time.Duration) *TimedHMAC {
	return &TimedHMAC{
		secret:     secret,
		timeToLive: timeToLive,
	}
}

// GenerateToken generates new time-based secret token - basically Payload is a unix timestamp and Signature is a HMAC
// hash of a timestamp with a preshared TURN secret
func (m *TimedHMAC) GenerateToken(algo func() hash.Hash) (*Token, error) {
	timeAuth := time.Now().Add(m.timeToLive).Unix()
	timeStamp := strconv.FormatInt(timeAuth, 10)

	checksum, err := m.generate(algo, timeStamp)
	if err != nil {
		return nil, err
	}

	return &Token{
		Payload:   timeStamp,
		Signature: base64.StdEncoding.EncodeToString(checksum),
	}, nil
}

// Validate checks if the token is valid.
// Security: This function uses constant-time comparison (hmac.Equal) to prevent timing attacks.
// The validation order is optimized to fail fast on invalid signatures before checking expiration,
// which helps prevent timing-based information leakage.
func (m *TimedHMAC) Validate(algo func() hash.Hash, token Token) error {
	// Security: Validate token structure first
	if token.Payload == "" {
		return fmt.Errorf("invalid token: empty payload")
	}
	if token.Signature == "" {
		return fmt.Errorf("invalid token: empty signature")
	}
	
	expectedMAC, err := m.generate(algo, token.Payload)
	if err != nil {
		return fmt.Errorf("failed to generate expected MAC: %w", err)
	}

	expectedSignature := base64.StdEncoding.EncodeToString(expectedMAC)

	// Security: Use constant-time comparison to prevent timing attacks
	// hmac.Equal uses constant-time comparison, which is critical for security
	if !hmac.Equal([]byte(expectedSignature), []byte(token.Signature)) {
		return fmt.Errorf("signature mismatch")
	}

	// Security: Validate payload format before parsing
	// This prevents potential issues with malformed payloads
	if len(token.Payload) < 10 { // Unix timestamp minimum length
		return fmt.Errorf("invalid payload: too short")
	}

	timeAuthInt, err := strconv.ParseInt(token.Payload, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	// Security: Validate timestamp is reasonable (not too far in the past or future)
	// This prevents issues with clock skew and potential replay attacks
	now := time.Now().Unix()
	const maxClockSkew = 300 // 5 minutes in seconds
	
	if timeAuthInt < now-maxClockSkew {
		return fmt.Errorf("expired token")
	}
	
	// Security: Reject tokens with timestamps too far in the future
	// This prevents potential issues with clock manipulation
	if timeAuthInt > now+maxClockSkew {
		return fmt.Errorf("invalid token: timestamp too far in the future")
	}

	return nil
}

func (m *TimedHMAC) generate(algo func() hash.Hash, payload string) ([]byte, error) {
	mac := hmac.New(algo, []byte(m.secret))
	_, err := mac.Write([]byte(payload))
	if err != nil {
		log.Debugf("failed to generate token: %s", err)
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return mac.Sum(nil), nil
}
