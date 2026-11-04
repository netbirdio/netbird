package mcpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

type scopesKey struct{}

// AuthMiddleware wraps the API auth middleware so the MCP endpoint also accepts the broker's
// access tokens. Every other credential, and a broker token presented anywhere but the MCP
// endpoint, goes to apiAuth, which rejects what it does not know.
func (b *Broker) AuthMiddleware(apiAuth mux.MiddlewareFunc) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		fallback := apiAuth(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := brokerToken(r)
			if !ok || r.URL.Path != apiPrefix+Path {
				fallback.ServeHTTP(w, r)
				return
			}

			userAuth, scopes, err := b.authenticate(r, token)
			if errors.Is(err, errStoreUnavailable) {
				// Not the token's fault: a 401 would send the client through a new sign-in.
				log.WithContext(r.Context()).Errorf("MCP OAuth: %v", err)
				util.WriteErrorResponse("temporarily unavailable, try again shortly", http.StatusServiceUnavailable, w)
				return
			}
			if err != nil {
				log.WithContext(r.Context()).Debugf("MCP access token rejected: %v", err)
				util.WriteErrorResponse("invalid or expired MCP access token", http.StatusUnauthorized, w)
				return
			}
			if b.limiter != nil && !b.limiter.Allow("mcp-oauth:"+userAuth.UserId) {
				util.WriteErrorResponse("too many requests", http.StatusTooManyRequests, w)
				return
			}

			ctx := context.WithValue(nbcontext.SetUserAuthInContext(r.Context(), userAuth), scopesKey{}, scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func brokerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || !strings.HasPrefix(token, accessTokenPrefix) {
		return "", false
	}
	return token, true
}

// authenticate checks the token is the broker's, unexpired and issued for this endpoint, then
// reloads the user so a blocked or removed user loses access on the next call.
func (b *Broker) authenticate(r *http.Request, token string) (auth.UserAuth, []string, error) {
	var g grant
	if err := b.seal.open(purposeAccess, accessTokenPrefix, token, &g); err != nil {
		return auth.UserAuth{}, nil, err
	}
	if b.expired(g.Expires) {
		return auth.UserAuth{}, nil, errors.New("token expired")
	}
	if g.Resource != b.resourceURL(r) {
		return auth.UserAuth{}, nil, errors.New("token was issued for another resource")
	}
	// Checking the grant on every call is what makes revoking one session immediate.
	record, ok, err := b.grants.load(r.Context(), g.GrantID)
	if err != nil {
		return auth.UserAuth{}, nil, err
	}
	if !ok || !record.belongsTo(g) {
		return auth.UserAuth{}, nil, errors.New("the session was revoked or has ended")
	}
	user, err := b.activeIdentity(r.Context(), g.Identity, record.Started)
	if err != nil {
		return auth.UserAuth{}, nil, err
	}
	return auth.UserAuth{
		UserId:         user.Id,
		AccountId:      g.Identity.AccountID,
		Domain:         g.Identity.Domain,
		DomainCategory: g.Identity.DomainCategory,
		IsPAT:          true,
	}, g.Scopes, nil
}

// writeAllowed reports whether the caller may run tools that change data. Callers that
// authenticated with a PAT or a dashboard JWT carry no MCP scopes and keep their full role.
func writeAllowed(ctx context.Context) bool {
	scopes, ok := ctx.Value(scopesKey{}).([]string)
	if !ok {
		return true
	}
	return slices.Contains(scopes, scopeWrite)
}
