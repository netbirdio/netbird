package hmac

import (
	"crypto/sha256"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

type TimedHMACValidator struct {
	*TimedHMAC
}

func NewTimedHMACValidator(secret string, duration time.Duration) *TimedHMACValidator {
	ta := NewTimedHMAC(secret, duration)
	return &TimedHMACValidator{
		ta,
	}
}

func (a *TimedHMACValidator) Validate(credentials any) error {
	b, ok := credentials.([]byte)
	if !ok {
		return fmt.Errorf("invalid credentials type")
	}
	c, err := unmarshalToken(b)
	if err != nil {
		log.Debugf("failed to unmarshal token: %s", err)
		return err
	}
	return a.TimedHMAC.Validate(sha256.New, c)
}
