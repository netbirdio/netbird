package v2

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

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

	if len(token.Payload) < 8 {
		return errors.New("invalid payload: insufficient length")
	}

	timestamp := int64(binary.BigEndian.Uint64(token.Payload[:8]))
	if time.Now().Unix() > timestamp {
		return errors.New("token expired")
	}

	return nil
}
