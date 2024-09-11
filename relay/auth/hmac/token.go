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

// Validate checks if the token is valid
func (m *TimedHMAC) Validate(algo func() hash.Hash, token Token) error {
	expectedMAC, err := m.generate(algo, token.Payload)
	if err != nil {
		return err
	}

	expectedSignature := base64.StdEncoding.EncodeToString(expectedMAC)

	if !hmac.Equal([]byte(expectedSignature), []byte(token.Signature)) {
		return fmt.Errorf("signature mismatch")
	}

	timeAuthInt, err := strconv.ParseInt(token.Payload, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	if time.Now().Unix() > timeAuthInt {
		return fmt.Errorf("expired token")
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
