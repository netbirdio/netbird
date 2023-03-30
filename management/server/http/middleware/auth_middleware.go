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

// AuthMiddleware middleware to verify personal access tokens (PAT) and JWT tokens
type AuthMiddleware struct {
	getAccountFromPAT     GetAccountFromPATFunc
	validateAndParseToken ValidateAndParseTokenFunc
	markPATUsed           MarkPATUsedFunc
	audience              string
}

type key string

const (
	userProperty key = "user"
)

// NewAuthMiddleware instance constructor
func NewAuthMiddleware(getAccountFromPAT GetAccountFromPATFunc, validateAndParseToken ValidateAndParseTokenFunc, markPATUsed MarkPATUsedFunc, audience string) *AuthMiddleware {
	return &AuthMiddleware{
		getAccountFromPAT:     getAccountFromPAT,
		validateAndParseToken: validateAndParseToken,
		markPATUsed:           markPATUsed,
		audience:              audience,
	}
}

// Handler method of the middleware which authenticates a user either by JWT claims or by PAT
func (m *AuthMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.Split(r.Header.Get("Authorization"), " ")
		authType := auth[0]
		switch strings.ToLower(authType) {
		case "bearer":
			err := m.CheckJWTFromRequest(w, r)
			if err != nil {
				log.Debugf("Error when validating JWT claims: %s", err.Error())
				util.WriteError(status.Errorf(status.Unauthorized, "Token invalid"), w)
				return
			}
			h.ServeHTTP(w, r)
		case "token":
			err := m.CheckPATFromRequest(w, r)
			if err != nil {
				log.Debugf("Error when validating PAT claims: %s", err.Error())
				util.WriteError(status.Errorf(status.Unauthorized, "Token invalid"), w)
				return
			}
			h.ServeHTTP(w, r)
		default:
			util.WriteError(status.Errorf(status.Unauthorized, "No valid authentication provided"), w)
			return
		}
	})
}

// CheckJWTFromRequest checks if the JWT is valid
func (m *AuthMiddleware) CheckJWTFromRequest(w http.ResponseWriter, r *http.Request) error {

	token, err := getTokenFromJWTRequest(r)

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

	// If we get here, everything worked and we can set the
	// user property in context.
	newRequest := r.WithContext(context.WithValue(r.Context(), userProperty, validatedToken)) // nolint
	// Update the current request with the new context information.
	*r = *newRequest
	return nil
}

// CheckPATFromRequest checks if the PAT is valid
func (m *AuthMiddleware) CheckPATFromRequest(w http.ResponseWriter, r *http.Request) error {
	token, err := getTokenFromPATRequest(r)

	// If an error occurs, call the error handler and return an error
	if err != nil {
		return fmt.Errorf("Error extracting token: %w", err)
	}

	account, user, pat, err := m.getAccountFromPAT(token)
	if err != nil {
		util.WriteError(status.Errorf(status.Unauthorized, "Token invalid"), w)
		return fmt.Errorf("invalid Token: %w", err)
	}
	if time.Now().After(pat.ExpirationDate) {
		util.WriteError(status.Errorf(status.Unauthorized, "Token expired"), w)
		return fmt.Errorf("token expired")
	}

	err = m.markPATUsed(pat.ID)
	if err != nil {
		return err
	}

	claimMaps := jwt.MapClaims{}
	claimMaps[string(jwtclaims.UserIDClaim)] = user.Id
	claimMaps[m.audience+string(jwtclaims.AccountIDSuffix)] = account.Id
	claimMaps[m.audience+string(jwtclaims.DomainIDSuffix)] = account.Domain
	claimMaps[m.audience+string(jwtclaims.DomainCategorySuffix)] = account.DomainCategory
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claimMaps)
	newRequest := r.WithContext(context.WithValue(r.Context(), jwtclaims.TokenUserProperty, jwtToken))
	// Update the current request with the new context information.
	*r = *newRequest
	return nil
}

// getTokenFromJWTRequest is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func getTokenFromJWTRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// getTokenFromPATRequest is a "TokenExtractor" that takes a give request and extracts
// the PAT token from the Authorization header.
func getTokenFromPATRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "token" {
		return "", errors.New("Authorization header format must be Token {token}")
	}

	return authHeaderParts[1], nil
}
