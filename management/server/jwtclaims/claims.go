package jwtclaims

// AuthorizationClaims stores authorization information from JWTs
type AuthorizationClaims struct {
	UserId         string
	AccountId      string
	Domain         string
	DomainCategory string
}
