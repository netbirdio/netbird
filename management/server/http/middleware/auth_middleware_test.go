package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/management/server/util"

	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	audience       = "audience"
	userIDClaim    = "userIDClaim"
	accountID      = "accountID"
	domain         = "domain"
	domainCategory = "domainCategory"
	userID         = "userID"
	tokenID        = "tokenID"
	PAT            = "nbp_PAT"
	JWT            = "JWT"
	wrongToken     = "wrongToken"
)

var testAccount = &types.Account{
	Id:     accountID,
	Domain: domain,
	Users: map[string]*types.User{
		userID: {
			Id:        userID,
			AccountID: accountID,
			PATs: map[string]*types.PersonalAccessToken{
				tokenID: {
					ID:             tokenID,
					Name:           "My first token",
					HashedToken:    "someHash",
					ExpirationDate: util.ToPtr(time.Now().UTC().AddDate(0, 0, 7)),
					CreatedBy:      userID,
					CreatedAt:      time.Now().UTC(),
					LastUsed:       util.ToPtr(time.Now().UTC()),
				},
			},
		},
	},
}

func mockGetAccountInfoFromPAT(_ context.Context, token string) (user *types.User, pat *types.PersonalAccessToken, domain string, category string, err error) {
	if token == PAT {
		return testAccount.Users[userID], testAccount.Users[userID].PATs[tokenID], testAccount.Domain, testAccount.DomainCategory, nil
	}
	return nil, nil, "", "", fmt.Errorf("PAT invalid")
}

func mockValidateAndParseToken(_ context.Context, token string) (*jwt.Token, error) {
	if token == JWT {
		return &jwt.Token{
			Claims: jwt.MapClaims{
				userIDClaim:                          userID,
				audience + jwtclaims.AccountIDSuffix: accountID,
			},
			Valid: true,
		}, nil
	}
	return nil, fmt.Errorf("JWT invalid")
}

func mockMarkPATUsed(_ context.Context, token string) error {
	if token == tokenID {
		return nil
	}
	return fmt.Errorf("Should never get reached")
}

func mockCheckUserAccessByJWTGroups(_ context.Context, claims jwtclaims.AuthorizationClaims) error {
	if testAccount.Id != claims.AccountId {
		return fmt.Errorf("account with id %s does not exist", claims.AccountId)
	}

	if _, ok := testAccount.Users[claims.UserId]; !ok {
		return fmt.Errorf("user with id %s does not exist", claims.UserId)
	}

	return nil
}

func TestAuthMiddleware_Handler(t *testing.T) {
	tt := []struct {
		name               string
		path               string
		authHeader         string
		expectedStatusCode int
		shouldBypassAuth   bool
	}{
		{
			name:               "Valid PAT Token",
			path:               "/test",
			authHeader:         "Token " + PAT,
			expectedStatusCode: 200,
		},
		{
			name:               "Invalid PAT Token",
			path:               "/test",
			authHeader:         "Token " + wrongToken,
			expectedStatusCode: 401,
		},
		{
			name:               "Fallback to PAT Token",
			path:               "/test",
			authHeader:         "Bearer " + PAT,
			expectedStatusCode: 200,
		},
		{
			name:               "Valid JWT Token",
			path:               "/test",
			authHeader:         "Bearer " + JWT,
			expectedStatusCode: 200,
		},
		{
			name:               "Invalid JWT Token",
			path:               "/test",
			authHeader:         "Bearer " + wrongToken,
			expectedStatusCode: 401,
		},
		{
			name:               "Basic Auth",
			path:               "/test",
			authHeader:         "Basic  " + PAT,
			expectedStatusCode: 401,
		},
		{
			name:               "Webhook Path Bypass",
			path:               "/webhook",
			authHeader:         "",
			expectedStatusCode: 200,
			shouldBypassAuth:   true,
		},
		{
			name:               "Webhook Path Bypass with Subpath",
			path:               "/webhook/test",
			authHeader:         "",
			expectedStatusCode: 200,
			shouldBypassAuth:   true,
		},
		{
			name:               "Different Webhook Path",
			path:               "/webhooktest",
			authHeader:         "",
			expectedStatusCode: 401,
			shouldBypassAuth:   false,
		},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// do nothing
	})

	claimsExtractor := jwtclaims.NewClaimsExtractor(
		jwtclaims.WithAudience(audience),
		jwtclaims.WithUserIDClaim(userIDClaim),
	)

	authMiddleware := NewAuthMiddleware(
		mockGetAccountInfoFromPAT,
		mockValidateAndParseToken,
		mockMarkPATUsed,
		mockCheckUserAccessByJWTGroups,
		claimsExtractor,
		audience,
		userIDClaim,
	)

	handlerToTest := authMiddleware.Handler(nextHandler)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldBypassAuth {
				err := bypass.AddBypassPath(tc.path)
				if err != nil {
					t.Fatalf("failed to add bypass path: %v", err)
				}
			}

			req := httptest.NewRequest("GET", "http://testing"+tc.path, nil)
			req.Header.Set("Authorization", tc.authHeader)
			rec := httptest.NewRecorder()

			handlerToTest.ServeHTTP(rec, req)

			result := rec.Result()
			defer result.Body.Close()
			if result.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected status code %d, got %d", tc.expectedStatusCode, result.StatusCode)
			}
		})
	}
}
