package jwt

import (
	"errors"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/auth"
)

const (
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

var (
	errUserIDClaimEmpty = errors.New("user ID claim token value is empty")
)

// ClaimsExtractor struct that holds the extract function
type ClaimsExtractor struct {
	authAudience string
	userIDClaim  string
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

// NewClaimsExtractor returns an extractor, and if provided with a function with ExtractClaims signature,
// then it will use that logic. Uses ExtractClaimsFromRequestContext by default
func NewClaimsExtractor(options ...ClaimsExtractorOption) *ClaimsExtractor {
	ce := &ClaimsExtractor{}
	for _, option := range options {
		option(ce)
	}

	if ce.userIDClaim == "" {
		ce.userIDClaim = UserIDClaim
	}
	return ce
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

func (c *ClaimsExtractor) audienceClaim(claimName string) string {
	audienceURL, err := url.JoinPath(c.authAudience, claimName)
	if err != nil {
		return c.authAudience + claimName // as it was previously
	}

	return audienceURL
}

// ToUserAuth extracts user authentication information from a JWT token.
// The token should contain standard claims like email, name, preferred_username.
// When using Dex, make sure to set getUserInfo: true to have these claims populated.
func (c *ClaimsExtractor) ToUserAuth(token *jwt.Token) (auth.UserAuth, error) {
	claims := token.Claims.(jwt.MapClaims)
	userAuth := auth.UserAuth{}

	userID, ok := claims[c.userIDClaim].(string)
	if !ok {
		return userAuth, errUserIDClaimEmpty
	}
	userAuth.UserId = userID

	if accountIDClaim, ok := claims[c.audienceClaim(AccountIDSuffix)]; ok {
		userAuth.AccountId = accountIDClaim.(string)
	}

	if domainClaim, ok := claims[c.audienceClaim(DomainIDSuffix)]; ok {
		userAuth.Domain = domainClaim.(string)
	}

	if domainCategoryClaim, ok := claims[c.audienceClaim(DomainCategorySuffix)]; ok {
		userAuth.DomainCategory = domainCategoryClaim.(string)
	}

	if lastLoginClaimString, ok := claims[c.audienceClaim(LastLoginSuffix)]; ok {
		userAuth.LastLogin = parseTime(lastLoginClaimString.(string))
	}

	if invitedBool, ok := claims[c.audienceClaim(Invited)]; ok {
		if value, ok := invitedBool.(bool); ok {
			userAuth.Invited = value
		}
	}

	// Extract email from standard "email" claim
	if email, ok := claims["email"].(string); ok {
		userAuth.Email = email
	}

	// Extract name from standard "name" claim
	if name, ok := claims["name"].(string); ok {
		userAuth.Name = name
	}

	// Extract name from standard "preferred_username" claim
	if preferredName, ok := claims["preferred_username"].(string); ok {
		userAuth.PreferredName = preferredName
	}

	return userAuth, nil
}

// ToGroups extracts group information from a JWT token
func (c *ClaimsExtractor) ToGroups(token *jwt.Token, claimName string) []string {
	claims := token.Claims.(jwt.MapClaims)
	userJWTGroups := make([]string, 0)

	if claim, ok := claims[claimName]; ok {
		if claimGroups, ok := claim.([]interface{}); ok {
			for _, g := range claimGroups {
				if group, ok := g.(string); ok {
					userJWTGroups = append(userJWTGroups, group)
				} else {
					log.Debugf("JWT claim %q contains a non-string group (type: %T): %v", claimName, g, g)
				}
			}
		}
	} else {
		log.Debugf("JWT claim %q is not a string array", claimName)
	}

	return userJWTGroups
}
