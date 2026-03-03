package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/management-integrations/integrations"
	serverauth "github.com/netbirdio/netbird/management/server/auth"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type EnsureAccountFunc func(ctx context.Context, userAuth auth.UserAuth) (string, string, error)
type SyncUserJWTGroupsFunc func(ctx context.Context, userAuth auth.UserAuth) error

type GetUserFromUserAuthFunc func(ctx context.Context, userAuth auth.UserAuth) (*types.User, error)

// AuthMiddleware middleware to verify personal access tokens (PAT) and JWT tokens
type AuthMiddleware struct {
	authManager         serverauth.Manager
	ensureAccount       EnsureAccountFunc
	getUserFromUserAuth GetUserFromUserAuthFunc
	syncUserJWTGroups   SyncUserJWTGroupsFunc
	rateLimiter         *APIRateLimiter
	patUsageTracker     *PATUsageTracker
}

// NewAuthMiddleware instance constructor
func NewAuthMiddleware(
	authManager serverauth.Manager,
	ensureAccount EnsureAccountFunc,
	syncUserJWTGroups SyncUserJWTGroupsFunc,
	getUserFromUserAuth GetUserFromUserAuthFunc,
	rateLimiterConfig *RateLimiterConfig,
	meter metric.Meter,
) *AuthMiddleware {
	var rateLimiter *APIRateLimiter
	if rateLimiterConfig != nil {
		rateLimiter = NewAPIRateLimiter(rateLimiterConfig)
	}

	var patUsageTracker *PATUsageTracker
	if meter != nil {
		var err error
		patUsageTracker, err = NewPATUsageTracker(context.Background(), meter)
		if err != nil {
			log.Errorf("Failed to create PAT usage tracker: %s", err)
		}
	}

	return &AuthMiddleware{
		authManager:         authManager,
		ensureAccount:       ensureAccount,
		syncUserJWTGroups:   syncUserJWTGroups,
		getUserFromUserAuth: getUserFromUserAuth,
		rateLimiter:         rateLimiter,
		patUsageTracker:     patUsageTracker,
	}
}

// Handler method of the middleware which authenticates a user either by JWT claims or by PAT
func (m *AuthMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bypass.ShouldBypass(r.URL.Path, h, w, r) {
			return
		}

		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		authType := strings.ToLower(authHeader[0])

		// fallback to token when receive pat as bearer
		if len(authHeader) >= 2 && authType == "bearer" && strings.HasPrefix(authHeader[1], "nbp_") {
			authType = "token"
			authHeader[0] = authType
		}

		switch authType {
		case "bearer":
			request, err := m.checkJWTFromRequest(r, authHeader)
			if err != nil {
				log.WithContext(r.Context()).Errorf("Error when validating JWT: %s", err.Error())
				util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "token invalid"), w)
				return
			}

			h.ServeHTTP(w, request)
		case "token":
			request, err := m.checkPATFromRequest(r, authHeader)
			if err != nil {
				log.WithContext(r.Context()).Debugf("Error when validating PAT: %s", err.Error())
				// Check if it's a status error, otherwise default to Unauthorized
				if _, ok := status.FromError(err); !ok {
					err = status.Errorf(status.Unauthorized, "token invalid")
				}
				util.WriteError(r.Context(), err, w)
				return
			}
			h.ServeHTTP(w, request)
		default:
			util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "no valid authentication provided"), w)
			return
		}
	})
}

// CheckJWTFromRequest checks if the JWT is valid
func (m *AuthMiddleware) checkJWTFromRequest(r *http.Request, authHeaderParts []string) (*http.Request, error) {
	token, err := getTokenFromJWTRequest(authHeaderParts)

	// If an error occurs, call the error handler and return an error
	if err != nil {
		return r, fmt.Errorf("error extracting token: %w", err)
	}

	ctx := r.Context()

	userAuth, validatedToken, err := m.authManager.ValidateAndParseToken(ctx, token)
	if err != nil {
		return r, err
	}

	if impersonate, ok := r.URL.Query()["account"]; ok && len(impersonate) == 1 {
		if integrations.IsValidChildAccount(ctx, userAuth.UserId, userAuth.AccountId, impersonate[0]) {
			userAuth.AccountId = impersonate[0]
			userAuth.IsChild = true
		}
	}

	// Email is now extracted in ToUserAuth (from claims or userinfo endpoint)
	// Available as userAuth.Email

	// we need to call this method because if user is new, we will automatically add it to existing or create a new account
	accountId, _, err := m.ensureAccount(ctx, userAuth)
	if err != nil {
		return r, err
	}

	if userAuth.AccountId != accountId {
		log.WithContext(ctx).Tracef("Auth middleware sets accountId from ensure, before %s, now %s", userAuth.AccountId, accountId)
		userAuth.AccountId = accountId
	}

	userAuth, err = m.authManager.EnsureUserAccessByJWTGroups(ctx, userAuth, validatedToken)
	if err != nil {
		return r, err
	}

	err = m.syncUserJWTGroups(ctx, userAuth)
	if err != nil {
		log.WithContext(ctx).Errorf("HTTP server failed to sync user JWT groups: %s", err)
	}

	_, err = m.getUserFromUserAuth(ctx, userAuth)
	if err != nil {
		log.WithContext(ctx).Errorf("HTTP server failed to update user from user auth: %s", err)
		return r, err
	}

	return nbcontext.SetUserAuthInRequest(r, userAuth), nil
}

// CheckPATFromRequest checks if the PAT is valid
func (m *AuthMiddleware) checkPATFromRequest(r *http.Request, authHeaderParts []string) (*http.Request, error) {
	token, err := getTokenFromPATRequest(authHeaderParts)
	if err != nil {
		return r, fmt.Errorf("error extracting token: %w", err)
	}

	if m.patUsageTracker != nil {
		m.patUsageTracker.IncrementUsage(token)
	}

	if m.rateLimiter != nil && !isTerraformRequest(r) {
		if !m.rateLimiter.Allow(token) {
			return r, status.Errorf(status.TooManyRequests, "too many requests")
		}
	}

	ctx := r.Context()
	user, pat, accDomain, accCategory, err := m.authManager.GetPATInfo(ctx, token)
	if err != nil {
		return r, fmt.Errorf("invalid Token: %w", err)
	}
	if time.Now().After(pat.GetExpirationDate()) {
		return r, fmt.Errorf("token expired")
	}

	err = m.authManager.MarkPATUsed(ctx, pat.ID)
	if err != nil {
		return r, err
	}

	userAuth := auth.UserAuth{
		UserId:         user.Id,
		AccountId:      user.AccountID,
		Domain:         accDomain,
		DomainCategory: accCategory,
		IsPAT:          true,
	}

	if impersonate, ok := r.URL.Query()["account"]; ok && len(impersonate) == 1 {
		if integrations.IsValidChildAccount(r.Context(), userAuth.UserId, userAuth.AccountId, impersonate[0]) {
			userAuth.AccountId = impersonate[0]
			userAuth.IsChild = true
		}
	}

	return nbcontext.SetUserAuthInRequest(r, userAuth), nil
}

func isTerraformRequest(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	return strings.Contains(ua, "terraform")
}

// getTokenFromJWTRequest is a "TokenExtractor" that takes auth header parts and extracts
// the JWT token from the Authorization header.
func getTokenFromJWTRequest(authHeaderParts []string) (string, error) {
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// getTokenFromPATRequest is a "TokenExtractor" that takes auth header parts and extracts
// the PAT token from the Authorization header.
func getTokenFromPATRequest(authHeaderParts []string) (string, error) {
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "token" {
		return "", errors.New("authorization header format must be Token {token}")
	}

	return authHeaderParts[1], nil
}
