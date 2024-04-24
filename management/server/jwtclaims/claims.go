package jwtclaims

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// AuthorizationClaims stores authorization information from JWTs
type AuthorizationClaims struct {
	UserId         string
	AccountId      string
	Domain         string
	DomainCategory string
	LastLogin      time.Time
	Invited        bool

	Raw jwt.MapClaims
}
