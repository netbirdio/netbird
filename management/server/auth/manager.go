package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/auth"

	"github.com/netbirdio/netbird/base62"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	nbjwt "github.com/netbirdio/netbird/shared/auth/jwt"
)

var _ Manager = (*manager)(nil)

// dexDiscoveryURL is the hardcoded local DEX OIDC discovery endpoint
const dexDiscoveryURL = "http://localhost/dex/.well-known/openid-configuration"

type Manager interface {
	ValidateAndParseToken(ctx context.Context, value string) (auth.UserAuth, *jwt.Token, error)
	EnsureUserAccessByJWTGroups(ctx context.Context, userAuth auth.UserAuth, token *jwt.Token) (auth.UserAuth, error)
	MarkPATUsed(ctx context.Context, tokenID string) error
	GetPATInfo(ctx context.Context, token string) (user *types.User, pat *types.PersonalAccessToken, domain string, category string, err error)
	GetUserEmail(ctx context.Context, token *jwt.Token, accessToken string) (string, error)
}

type manager struct {
	store store.Store

	issuer    string
	validator *nbjwt.Validator
	extractor *nbjwt.ClaimsExtractor

	httpClient *http.Client

	// userinfo endpoint caching (retries on failure)
	userInfoMu       sync.Mutex
	userInfoEndpoint string
}

func NewManager(store store.Store, issuer, audience, keysLocation, userIdClaim string, allAudiences []string, idpRefreshKeys bool) Manager {
	// @note if invalid/missing parameters are sent the validator will instantiate
	// but it will fail when validating and parsing the token
	jwtValidator := nbjwt.NewValidator(
		issuer,
		allAudiences,
		keysLocation,
		idpRefreshKeys,
	)

	claimsExtractor := nbjwt.NewClaimsExtractor(
		nbjwt.WithAudience(audience),
		nbjwt.WithUserIDClaim(userIdClaim),
	)

	return &manager{
		store: store,

		issuer:    issuer,
		validator: jwtValidator,
		extractor: claimsExtractor,
		httpClient: &http.Client{
			Timeout: time.Second,
		},
	}
}

func (m *manager) ValidateAndParseToken(ctx context.Context, value string) (auth.UserAuth, *jwt.Token, error) {
	token, err := m.validator.ValidateAndParse(ctx, value)
	if err != nil {
		return auth.UserAuth{}, nil, err
	}

	userAuth, err := m.extractor.ToUserAuth(token)
	if err != nil {
		return auth.UserAuth{}, nil, err
	}
	return userAuth, token, err
}

func (m *manager) EnsureUserAccessByJWTGroups(ctx context.Context, userAuth auth.UserAuth, token *jwt.Token) (auth.UserAuth, error) {
	if userAuth.IsChild || userAuth.IsPAT {
		return userAuth, nil
	}

	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		return userAuth, err
	}

	// Ensures JWT group synchronization to the management is enabled before,
	// filtering access based on the allowed groups.
	if settings != nil && settings.JWTGroupsEnabled {
		userAuth.Groups = m.extractor.ToGroups(token, settings.JWTGroupsClaimName)
		if allowedGroups := settings.JWTAllowGroups; len(allowedGroups) > 0 {
			if !userHasAllowedGroup(allowedGroups, userAuth.Groups) {
				return userAuth, fmt.Errorf("user does not belong to any of the allowed JWT groups")
			}
		}
	}

	return userAuth, nil
}

// MarkPATUsed marks a personal access token as used
func (am *manager) MarkPATUsed(ctx context.Context, tokenID string) error {
	return am.store.MarkPATUsed(ctx, tokenID)
}

// GetPATInfo retrieves user, personal access token, domain, and category details from a personal access token.
func (am *manager) GetPATInfo(ctx context.Context, token string) (user *types.User, pat *types.PersonalAccessToken, domain string, category string, err error) {
	user, pat, err = am.extractPATFromToken(ctx, token)
	if err != nil {
		return nil, nil, "", "", err
	}

	domain, category, err = am.store.GetAccountDomainAndCategory(ctx, store.LockingStrengthNone, user.AccountID)
	if err != nil {
		return nil, nil, "", "", err
	}

	return user, pat, domain, category, nil
}

// extractPATFromToken validates the token structure and retrieves associated User and PAT.
func (am *manager) extractPATFromToken(ctx context.Context, token string) (*types.User, *types.PersonalAccessToken, error) {
	if len(token) != types.PATLength {
		return nil, nil, fmt.Errorf("PAT has incorrect length")
	}

	prefix := token[:len(types.PATPrefix)]
	if prefix != types.PATPrefix {
		return nil, nil, fmt.Errorf("PAT has wrong prefix")
	}
	secret := token[len(types.PATPrefix) : len(types.PATPrefix)+types.PATSecretLength]
	encodedChecksum := token[len(types.PATPrefix)+types.PATSecretLength : len(types.PATPrefix)+types.PATSecretLength+types.PATChecksumLength]

	verificationChecksum, err := base62.Decode(encodedChecksum)
	if err != nil {
		return nil, nil, fmt.Errorf("PAT checksum decoding failed: %w", err)
	}

	secretChecksum := crc32.ChecksumIEEE([]byte(secret))
	if secretChecksum != verificationChecksum {
		return nil, nil, fmt.Errorf("PAT checksum does not match")
	}

	hashedToken := sha256.Sum256([]byte(token))
	encodedHashedToken := base64.StdEncoding.EncodeToString(hashedToken[:])

	var user *types.User
	var pat *types.PersonalAccessToken

	err = am.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		pat, err = transaction.GetPATByHashedToken(ctx, store.LockingStrengthNone, encodedHashedToken)
		if err != nil {
			return err
		}

		user, err = transaction.GetUserByPATID(ctx, store.LockingStrengthNone, pat.ID)
		return err
	})
	if err != nil {
		return nil, nil, err
	}

	return user, pat, nil
}

// userHasAllowedGroup checks if a user belongs to any of the allowed groups.
func userHasAllowedGroup(allowedGroups []string, userGroups []string) bool {
	for _, userGroup := range userGroups {
		for _, allowedGroup := range allowedGroups {
			if userGroup == allowedGroup {
				return true
			}
		}
	}
	return false
}

// GetUserEmail retrieves the user's email from the JWT token claims or by calling the userinfo endpoint.
// First tries to extract email from token claims, if not present, calls the OIDC userinfo endpoint.
func (m *manager) GetUserEmail(ctx context.Context, token *jwt.Token, accessToken string) (string, error) {
	// First, try to get email from token claims
	email := m.extractor.ToEmail(token)
	if email != "" {
		return email, nil
	}

	// Email not in token, need to call userinfo endpoint
	userInfoEndpoint, err := m.getUserInfoEndpoint(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get userinfo endpoint: %w", err)
	}

	email, err = m.fetchEmailFromUserInfo(ctx, userInfoEndpoint, accessToken)
	if err != nil {
		return "", fmt.Errorf("failed to fetch email from userinfo: %w", err)
	}

	return email, nil
}

// getUserInfoEndpoint returns the cached userinfo endpoint, discovering it on first call.
// If discovery fails, it will retry on subsequent calls.
func (m *manager) getUserInfoEndpoint(ctx context.Context) (string, error) {
	m.userInfoMu.Lock()
	defer m.userInfoMu.Unlock()

	// Return cached endpoint if already discovered
	if m.userInfoEndpoint != "" {
		return m.userInfoEndpoint, nil
	}

	// Discover and cache
	endpoint, err := m.discoverUserInfoEndpoint(ctx)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to discover userinfo endpoint: %v", err)
		return "", err
	}

	m.userInfoEndpoint = endpoint
	log.WithContext(ctx).Infof("discovered userinfo endpoint: %s", m.userInfoEndpoint)
	return m.userInfoEndpoint, nil
}

// oidcDiscoveryResponse represents the OIDC discovery document
type oidcDiscoveryResponse struct {
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

// discoverUserInfoEndpoint discovers the userinfo endpoint from the OIDC discovery document
// Uses hardcoded local DEX discovery URL
func (m *manager) discoverUserInfoEndpoint(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dexDiscoveryURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery oidcDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", err
	}

	if discovery.UserinfoEndpoint == "" {
		return "", fmt.Errorf("userinfo_endpoint not found in OIDC discovery document")
	}

	return discovery.UserinfoEndpoint, nil
}

// userInfoResponse represents the userinfo response
type userInfoResponse struct {
	Email string `json:"email"`
}

// fetchEmailFromUserInfo fetches the user's email from the userinfo endpoint
func (m *manager) fetchEmailFromUserInfo(ctx context.Context, userInfoEndpoint, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	var userInfo userInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	if userInfo.Email == "" {
		log.WithContext(ctx).Debug("email not found in userinfo response")
	}

	return userInfo.Email, nil
}
