package jwtclaims

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	// TokenUserProperty key for the user property in the request context
	TokenUserProperty = "user"
	// AccountIDSuffix suffix for the account id claim
	AccountIDSuffix = "wt_account_id"
	// DomainIDSuffix suffix for the domain id claim
	DomainIDSuffix = "wt_account_domain"
	// DomainCategorySuffix suffix for the domain category claim
	DomainCategorySuffix = "wt_account_domain_category"
	// UserIDClaim claim for the user id
	UserIDClaim = "sub"
	// LastLoginSuffix claim for the last login
	LastLoginSuffix = "nb_last_login"
	// Invited claim indicates that an incoming JWT is from a user that just accepted an invitation
	Invited = "nb_invited"
)

// ExtractClaims Extract function type
type ExtractClaims func(r *http.Request) AuthorizationClaims

// ClaimsExtractor struct that holds the extract function
type ClaimsExtractor struct {
	authAudience string
	userIDClaim  string

	FromRequestContext ExtractClaims
}

// ClaimsExtractorOption is a function that configures the ClaimsExtractor
type ClaimsExtractorOption func(*ClaimsExtractor)

// WithAudience sets the audience for the extractor
func WithAudience(audience string) ClaimsExtractorOption {
	return func(c *ClaimsExtractor) {
		c.authAudience = audience
	}
}

// WithUserIDClaim sets the user id claim for the extractor
func WithUserIDClaim(userIDClaim string) ClaimsExtractorOption {
	return func(c *ClaimsExtractor) {
		c.userIDClaim = userIDClaim
	}
}

// WithFromRequestContext sets the function that extracts claims from the request context
func WithFromRequestContext(ec ExtractClaims) ClaimsExtractorOption {
	return func(c *ClaimsExtractor) {
		c.FromRequestContext = ec
	}
}

// NewClaimsExtractor returns an extractor, and if provided with a function with ExtractClaims signature,
// then it will use that logic. Uses ExtractClaimsFromRequestContext by default
func NewClaimsExtractor(options ...ClaimsExtractorOption) *ClaimsExtractor {
	ce := &ClaimsExtractor{}
	for _, option := range options {
		option(ce)
	}
	if ce.FromRequestContext == nil {
		ce.FromRequestContext = ce.fromRequestContext
	}
	if ce.userIDClaim == "" {
		ce.userIDClaim = UserIDClaim
	}
	return ce
}

// FromToken extracts claims from the token (after auth)
func (c *ClaimsExtractor) FromToken(token *jwt.Token) AuthorizationClaims {
	claims := token.Claims.(jwt.MapClaims)
	jwtClaims := AuthorizationClaims{
		Raw: claims,
	}
	userID, ok := claims[c.userIDClaim].(string)
	if !ok {
		return jwtClaims
	}
	jwtClaims.UserId = userID
	accountIDClaim, ok := claims[c.authAudience+AccountIDSuffix]
	if ok {
		jwtClaims.AccountId = accountIDClaim.(string)
	}
	domainClaim, ok := claims[c.authAudience+DomainIDSuffix]
	if ok {
		jwtClaims.Domain = domainClaim.(string)
	}
	domainCategoryClaim, ok := claims[c.authAudience+DomainCategorySuffix]
	if ok {
		jwtClaims.DomainCategory = domainCategoryClaim.(string)
	}
	LastLoginClaimString, ok := claims[c.authAudience+LastLoginSuffix]
	if ok {
		jwtClaims.LastLogin = parseTime(LastLoginClaimString.(string))
	}
	invitedBool, ok := claims[c.authAudience+Invited]
	if ok {
		jwtClaims.Invited = invitedBool.(bool)
	}
	return jwtClaims
}

func parseTime(timeString string) time.Time {
	if timeString == "" {
		return time.Time{}
	}
	parsedTime, err := time.Parse(time.RFC3339, timeString)
	if err != nil {
		return time.Time{}
	}
	return parsedTime
}

// fromRequestContext extracts claims from the request context previously filled by the JWT token (after auth)
func (c *ClaimsExtractor) fromRequestContext(r *http.Request) AuthorizationClaims {
	if r.Context().Value(TokenUserProperty) == nil {
		return AuthorizationClaims{}
	}
	token := r.Context().Value(TokenUserProperty).(*jwt.Token)
	return c.FromToken(token)
}
