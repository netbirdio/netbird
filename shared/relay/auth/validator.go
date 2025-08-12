package auth

import (
	"time"

	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	authv2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

type TimedHMACValidator struct {
	authenticatorV2 *authv2.Validator
	authenticator   *auth.TimedHMACValidator
}

func NewTimedHMACValidator(secret []byte, duration time.Duration) *TimedHMACValidator {
	return &TimedHMACValidator{
		authenticatorV2: authv2.NewValidator(secret),
		authenticator:   auth.NewTimedHMACValidator(string(secret), duration),
	}
}

func (a *TimedHMACValidator) Validate(credentials any) error {
	return a.authenticatorV2.Validate(credentials)
}

func (a *TimedHMACValidator) ValidateHelloMsgType(credentials any) error {
	return a.authenticator.Validate(credentials)
}
