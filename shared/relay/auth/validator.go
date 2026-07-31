package auth

import (
	authv2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

type TimedHMACValidator struct {
	authenticatorV2 *authv2.Validator
}

func NewTimedHMACValidator(secret []byte) *TimedHMACValidator {
	return &TimedHMACValidator{
		authenticatorV2: authv2.NewValidator(secret),
	}
}

func (a *TimedHMACValidator) Validate(credentials any) error {
	return a.authenticatorV2.Validate(credentials)
}
