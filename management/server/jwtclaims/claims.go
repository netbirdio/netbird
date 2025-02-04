package jwtclaims

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// deprecated, use UserAuth instead
type AuthorizationClaims struct {
	UserId         string
	AccountId      string
	Domain         string
	DomainCategory string
	LastLogin      time.Time
	Invited        bool

	Raw jwt.MapClaims
}
