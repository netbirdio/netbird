package hmac

import (
	log "github.com/sirupsen/logrus"
	"time"
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
	b := credentials.([]byte)
	c, err := unmarshalToken(b)
	if err != nil {
		log.Errorf("failed to unmarshal token: %s", err)
		return err
	}
	return a.TimedHMAC.Validate(c)
}
