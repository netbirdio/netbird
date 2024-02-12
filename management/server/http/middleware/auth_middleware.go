package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// GetAccountFromPATFunc function
type GetAccountFromPATFunc func(token string) (*server.Account, *server.User, *server.PersonalAccessToken, error)

// ValidateAndParseTokenFunc function
type ValidateAndParseTokenFunc func(token string) (*jwt.Token, error)

// MarkPATUsedFunc function
type MarkPATUsedFunc func(token string) error

// CheckUserAccessByJWTGroupsFunc function
type CheckUserAccessByJWTGroupsFunc func(claims jwtclaims.AuthorizationClaims) error

// AuthMiddleware middleware to verify personal access tokens (PAT) and JWT tokens
type AuthMiddleware struct {
	getAccountFromPAT          GetAccountFromPATFunc
	validateAndParseToken      ValidateAndParseTokenFunc
	markPATUsed                MarkPATUsedFunc
	checkUserAccessByJWTGroups CheckUserAccessByJWTGroupsFunc
	claimsExtractor            *jwtclaims.ClaimsExtractor
	audience                   string
	userIDClaim                string
}

const (
	userProperty = "user"
)

// NewAuthMiddleware instance constructor
func NewAuthMiddleware(getAccountFromPAT GetAccountFromPATFunc, validateAndParseToken ValidateAndParseTokenFunc,
	markPATUsed MarkPATUsedFunc, checkUserAccessByJWTGroups CheckUserAccessByJWTGroupsFunc, claimsExtractor *jwtclaims.ClaimsExtractor,
	audience string, userIdClaim string) *AuthMiddleware {
	if userIdClaim == "" {
		userIdClaim = jwtclaims.UserIDClaim
	}

	return &AuthMiddleware{
		getAccountFromPAT:          getAccountFromPAT,
		validateAndParseToken:      validateAndParseToken,
		markPATUsed:                markPATUsed,
		checkUserAccessByJWTGroups: checkUserAccessByJWTGroups,
		claimsExtractor:            claimsExtractor,
		audience:                   audience,
		userIDClaim:                userIdClaim,
	}
}

// Handler method of the middleware which authenticates a user either by JWT claims or by PAT
func (m *AuthMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if bypass.ShouldBypass(r.URL.Path, h, w, r) {
			return
		}

		auth := strings.Split(r.Header.Get("Authorization"), " ")
		authType := strings.ToLower(auth[0])

		// fallback to token when receive pat as bearer
		if len(auth) >= 2 && authType == "bearer" && strings.HasPrefix(auth[1], "nbp_") {
			authType = "token"
			auth[0] = authType
		}

		switch authType {
		case "bearer":
			err := m.checkJWTFromRequest(w, r, auth)
			if err != nil {
				log.Errorf("Error when validating JWT claims: %s", err.Error())
				util.WriteError(status.Errorf(status.Unauthorized, "token invalid"), w)
				return
			}
			h.ServeHTTP(w, r)
		case "token":
			err := m.checkPATFromRequest(w, r, auth)
			if err != nil {
				log.Debugf("Error when validating PAT claims: %s", err.Error())
				util.WriteError(status.Errorf(status.Unauthorized, "token invalid"), w)
				return
			}
			h.ServeHTTP(w, r)
		default:
			util.WriteError(status.Errorf(status.Unauthorized, "no valid authentication provided"), w)
			return
		}
	})
}

// CheckJWTFromRequest checks if the JWT is valid
func (m *AuthMiddleware) checkJWTFromRequest(w http.ResponseWriter, r *http.Request, auth []string) error {
	token, err := getTokenFromJWTRequest(auth)

	// If an error occurs, call the error handler and return an error
	if err != nil {
		return fmt.Errorf("Error extracting token: %w", err)
	}

	validatedToken, err := m.validateAndParseToken(token)
	if err != nil {
		return err
	}

	if validatedToken == nil {
		return nil
	}

	if err := m.verifyUserAccess(validatedToken); err != nil {
		return err
	}

	// If we get here, everything worked and we can set the
	// user property in context.
	newRequest := r.WithContext(context.WithValue(r.Context(), userProperty, validatedToken)) //nolint
	// Update the current request with the new context information.
	*r = *newRequest
	return nil
}

// verifyUserAccess checks if a user, based on a validated JWT token,
// is allowed access, particularly in cases where the admin enabled JWT
// group propagation and designated certain groups with access permissions.
func (m *AuthMiddleware) verifyUserAccess(validatedToken *jwt.Token) error {
	authClaims := m.claimsExtractor.FromToken(validatedToken)
	return m.checkUserAccessByJWTGroups(authClaims)
}

// CheckPATFromRequest checks if the PAT is valid
func (m *AuthMiddleware) checkPATFromRequest(w http.ResponseWriter, r *http.Request, auth []string) error {
	token, err := getTokenFromPATRequest(auth)

	// If an error occurs, call the error handler and return an error
	if err != nil {
		return fmt.Errorf("Error extracting token: %w", err)
	}

	account, user, pat, err := m.getAccountFromPAT(token)
	if err != nil {
		return fmt.Errorf("invalid Token: %w", err)
	}
	if time.Now().After(pat.ExpirationDate) {
		return fmt.Errorf("token expired")
	}

	err = m.markPATUsed(pat.ID)
	if err != nil {
		return err
	}

	claimMaps := jwt.MapClaims{}
	claimMaps[m.userIDClaim] = user.Id
	claimMaps[m.audience+jwtclaims.AccountIDSuffix] = account.Id
	claimMaps[m.audience+jwtclaims.DomainIDSuffix] = account.Domain
	claimMaps[m.audience+jwtclaims.DomainCategorySuffix] = account.DomainCategory
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claimMaps)
	newRequest := r.WithContext(context.WithValue(r.Context(), jwtclaims.TokenUserProperty, jwtToken)) //nolint
	// Update the current request with the new context information.
	*r = *newRequest
	return nil
}

// getTokenFromJWTRequest is a "TokenExtractor" that takes auth header parts and extracts
// the JWT token from the Authorization header.
func getTokenFromJWTRequest(authHeaderParts []string) (string, error) {
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// getTokenFromPATRequest is a "TokenExtractor" that takes auth header parts and extracts
// the PAT token from the Authorization header.
func getTokenFromPATRequest(authHeaderParts []string) (string, error) {
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "token" {
		return "", errors.New("Authorization header format must be Token {token}")
	}

	return authHeaderParts[1], nil
}
