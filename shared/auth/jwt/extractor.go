package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
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

	// userinfo endpoint fetching
	userInfoDiscoveryURL string
	httpClient           *http.Client
	userInfoMu           sync.Mutex
	userInfoEndpoint     string
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

// WithUserInfoDiscoveryURL sets the OIDC discovery URL for fetching userinfo endpoint
func WithUserInfoDiscoveryURL(discoveryURL string) ClaimsExtractorOption {
	return func(c *ClaimsExtractor) {
		c.userInfoDiscoveryURL = discoveryURL
		c.httpClient = &http.Client{
			Timeout: time.Second,
		}
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
// If email is not in token claims and userinfo discovery URL is configured,
// it will fetch the email from the OIDC userinfo endpoint.
func (c *ClaimsExtractor) ToUserAuth(ctx context.Context, token *jwt.Token) (auth.UserAuth, error) {
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

	// If email not in claims and userinfo is configured, fetch from userinfo endpoint
	if userAuth.Email == "" && c.userInfoDiscoveryURL != "" {
		email, err := c.fetchEmailFromUserInfo(ctx, token.Raw)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to fetch email from /userinfo endpoint: %v", err)
		} else {
			userAuth.Email = email
		}
	}

	return userAuth, nil
}

// fetchEmailFromUserInfo fetches the user's email from the OIDC userinfo endpoint
func (c *ClaimsExtractor) fetchEmailFromUserInfo(ctx context.Context, accessToken string) (string, error) {
	userInfoEndpoint, err := c.getUserInfoEndpoint(ctx)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("userinfo endpoint returned non-200 status")
	}

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	return userInfo.Email, nil
}

// getUserInfoEndpoint returns the cached userinfo endpoint, discovering it on first call
func (c *ClaimsExtractor) getUserInfoEndpoint(ctx context.Context) (string, error) {
	if c.userInfoEndpoint != "" {
		return c.userInfoEndpoint, nil
	}

	c.userInfoMu.Lock()
	defer c.userInfoMu.Unlock()

	// Discover userinfo endpoint from OIDC discovery document
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoDiscoveryURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("OIDC discovery returned non-200 status")
	}

	var discovery struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", err
	}

	if discovery.UserinfoEndpoint == "" {
		return "", errors.New("userinfo_endpoint not found in OIDC discovery document")
	}

	c.userInfoEndpoint = discovery.UserinfoEndpoint
	log.WithContext(ctx).Infof("discovered userinfo endpoint: %s", c.userInfoEndpoint)
	return c.userInfoEndpoint, nil
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
