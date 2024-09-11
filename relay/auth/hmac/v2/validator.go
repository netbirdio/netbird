package v2

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const minLengthUnixTimestamp = 10

type Validator struct {
	secret []byte
}

func NewValidator(secret []byte) *Validator {
	return &Validator{secret: secret}
}

func (v *Validator) Validate(data any) error {
	d, ok := data.([]byte)
	if !ok {
		return fmt.Errorf("invalid data type")
	}

	token, err := UnmarshalToken(d)
	if err != nil {
		return fmt.Errorf("unmarshal token: %w", err)
	}

	if len(token.Payload) < minLengthUnixTimestamp {
		return errors.New("invalid payload: insufficient length")
	}

	hashFunc := token.AuthAlgo.New()
	if hashFunc == nil {
		return fmt.Errorf("unsupported auth algorithm: %s", token.AuthAlgo)
	}

	h := hmac.New(hashFunc, v.secret)
	h.Write(token.Payload)
	expectedMAC := h.Sum(nil)

	if !hmac.Equal(token.Signature, expectedMAC) {
		return errors.New("invalid signature")
	}

	timestamp, err := strconv.ParseInt(string(token.Payload), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	if time.Now().Unix() > timestamp {
		return fmt.Errorf("expired token")
	}

	return nil
}
