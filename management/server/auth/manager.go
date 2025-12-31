package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"

	"github.com/golang-jwt/jwt/v5"

	"github.com/netbirdio/netbird/shared/auth"

	"github.com/netbirdio/netbird/base62"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	nbjwt "github.com/netbirdio/netbird/shared/auth/jwt"
)

var _ Manager = (*manager)(nil)

type Manager interface {
	ValidateAndParseToken(ctx context.Context, value string) (auth.UserAuth, *jwt.Token, error)
	EnsureUserAccessByJWTGroups(ctx context.Context, userAuth auth.UserAuth, token *jwt.Token) (auth.UserAuth, error)
	MarkPATUsed(ctx context.Context, tokenID string) error
	GetPATInfo(ctx context.Context, token string) (user *types.User, pat *types.PersonalAccessToken, domain string, category string, err error)
}

type manager struct {
	store store.Store

	validator *nbjwt.Validator
	extractor *nbjwt.ClaimsExtractor
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
		store:     store,
		validator: jwtValidator,
		extractor: claimsExtractor,
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
