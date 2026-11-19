package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/auth"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	nbauth "github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/ratelimit"
	"github.com/netbirdio/netbird/trustedproxy"
)

func TestAuthMiddleware_ClientIPOnContext(t *testing.T) {
	trusted := trustedproxy.FromPrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	tests := []struct {
		name       string
		proxies    *trustedproxy.List
		remoteAddr string
		xff        string
		want       string
	}{
		{name: "direct connection", remoteAddr: "198.51.100.7:4242", want: "198.51.100.7"},
		{name: "forwarded header ignored without trusted proxies", remoteAddr: "198.51.100.7:4242", xff: "203.0.113.9", want: "198.51.100.7"},
		{name: "forwarded header ignored from untrusted peer", proxies: trusted, remoteAddr: "198.51.100.7:4242", xff: "203.0.113.9", want: "198.51.100.7"},
		{name: "forwarded header honoured from trusted proxy", proxies: trusted, remoteAddr: "10.1.2.3:4242", xff: "203.0.113.9, 10.9.9.9", want: "203.0.113.9"},
		{name: "v4-mapped remote address is unmapped", remoteAddr: "[::ffff:198.51.100.7]:4242", want: "198.51.100.7"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var seen netip.Addr
			var found bool

			mockAuth := &auth.MockManager{
				ValidateAndParseTokenFunc:       mockValidateAndParseToken,
				EnsureUserAccessByJWTGroupsFunc: mockEnsureUserAccessByJWTGroups,
			}
			limiter := ratelimit.NewAPIRateLimiter(nil)
			limiter.SetEnabled(false)

			authMiddleware := NewAuthMiddleware(
				mockAuth,
				func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
					return userAuth.AccountId, userAuth.UserId, nil
				},
				func(ctx context.Context, userAuth nbauth.UserAuth) error { return nil },
				func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
					seen, found = nbcontext.GetClientIP(ctx)
					return &types.User{}, nil
				},
				limiter,
				nil,
				tc.proxies,
			)

			req := httptest.NewRequest("GET", "http://testing/test", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			req.Header.Set("Authorization", "Bearer "+JWT)
			rec := httptest.NewRecorder()

			authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

			require.Equal(t, http.StatusOK, rec.Code)
			require.True(t, found, "client IP should be on the context passed to getUserFromUserAuth")
			assert.Equal(t, tc.want, seen.String())
		})
	}
}
