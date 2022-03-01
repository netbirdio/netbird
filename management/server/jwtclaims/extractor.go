package jwtclaims

import (
	"github.com/golang-jwt/jwt"
	"net/http"
)

const (
	TokenUserProperty    = "user"
	AccountIDSuffix      = "wt_account_id"
	DomainIDSuffix       = "wt_account_domain"
	DomainCategorySuffix = "wt_account_domain_category"
	UserIDClaim          = "sub"
)

// Extract function type
type ExtractClaims func(r *http.Request, authAudiance string) AuthorizationClaims

// ClaimsExtractor struct that holds the extract function
type ClaimsExtractor struct {
	ExtractClaimsFromRequestContext ExtractClaims
}

// NewClaimsExtractor returns an extractor, and if provided with a function with ExtractClaims signature,
// then it will use that logic. Uses ExtractClaimsFromRequestContext by default
func NewClaimsExtractor(e ExtractClaims) *ClaimsExtractor {
	var extractFunc ExtractClaims
	if extractFunc = e; extractFunc == nil {
		extractFunc = ExtractClaimsFromRequestContext
	}

	return &ClaimsExtractor{
		ExtractClaimsFromRequestContext: extractFunc,
	}
}

// ExtractClaimsFromRequestContext extracts claims from the request context previously filled by the JWT token (after auth)
func ExtractClaimsFromRequestContext(r *http.Request, authAudiance string) AuthorizationClaims {
	token := r.Context().Value(TokenUserProperty).(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	jwtClaims := AuthorizationClaims{}
	jwtClaims.UserId = claims[UserIDClaim].(string)
	accountIdClaim, ok := claims[authAudiance+AccountIDSuffix]
	if ok {
		jwtClaims.AccountId = accountIdClaim.(string)
	}
	domainClaim, ok := claims[authAudiance+DomainIDSuffix]
	if ok {
		jwtClaims.Domain = domainClaim.(string)
	}
	domainCategoryClaim, ok := claims[authAudiance+DomainCategorySuffix]
	if ok {
		jwtClaims.DomainCategory = domainCategoryClaim.(string)
	}
	return jwtClaims
}
