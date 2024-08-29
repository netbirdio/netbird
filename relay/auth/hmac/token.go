package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

type Token struct {
	Payload   string
	Signature string
}

func marshalToken(token Token) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(token)
	if err != nil {
		log.Debugf("failed to marshal token: %s", err)
		return nil, fmt.Errorf("failed to marshal token: %w", err)
	}
	return buffer.Bytes(), nil
}

func unmarshalToken(payload []byte) (Token, error) {
	var creds Token
	buffer := bytes.NewBuffer(payload)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(&creds)
	return creds, err
}

// TimedHMAC generates token with TTL and using pre-shared secret known to TURN server
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
func (m *TimedHMAC) GenerateToken() (*Token, error) {
	timeAuth := time.Now().Add(m.timeToLive).Unix()
	timeStamp := fmt.Sprint(timeAuth)

	checksum, err := m.generate(timeStamp)
	if err != nil {
		return nil, err
	}

	return &Token{
		Payload:   timeStamp,
		Signature: base64.StdEncoding.EncodeToString(checksum),
	}, nil
}

// Validate checks if the token is valid
func (m *TimedHMAC) Validate(token Token) error {
	expectedMAC, err := m.generate(token.Payload)
	if err != nil {
		return err
	}

	expectedSignature := base64.StdEncoding.EncodeToString(expectedMAC)

	if !hmac.Equal([]byte(expectedSignature), []byte(token.Signature)) {
		return fmt.Errorf("signature mismatch")
	}

	timeAuthInt, err := strconv.ParseInt(token.Payload, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid payload: %s", err)
	}

	if time.Now().Unix() > timeAuthInt {
		return fmt.Errorf("expired token")
	}

	return nil
}

func (m *TimedHMAC) generate(payload string) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(m.secret))
	_, err := mac.Write([]byte(payload))
	if err != nil {
		log.Debugf("failed to generate token: %s", err)
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return mac.Sum(nil), nil
}
