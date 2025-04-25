package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/auth"
	nbjwt "github.com/netbirdio/netbird/management/server/auth/jwt"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/util"

	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
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

func mockValidateAndParseToken(_ context.Context, token string) (nbcontext.UserAuth, *jwt.Token, error) {
	if token == JWT {
		return nbcontext.UserAuth{
				UserId:         userID,
				AccountId:      accountID,
				Domain:         testAccount.Domain,
				DomainCategory: testAccount.DomainCategory,
			},
			&jwt.Token{
				Claims: jwt.MapClaims{
					userIDClaim:                      userID,
					audience + nbjwt.AccountIDSuffix: accountID,
				},
				Valid: true,
			}, nil
	}
	return nbcontext.UserAuth{}, nil, fmt.Errorf("JWT invalid")
}

func mockMarkPATUsed(_ context.Context, token string) error {
	if token == tokenID {
		return nil
	}
	return fmt.Errorf("Should never get reached")
}

func mockEnsureUserAccessByJWTGroups(_ context.Context, userAuth nbcontext.UserAuth, token *jwt.Token) (nbcontext.UserAuth, error) {
	if userAuth.IsChild || userAuth.IsPAT {
		return userAuth, nil
	}

	if testAccount.Id != userAuth.AccountId {
		return userAuth, fmt.Errorf("account with id %s does not exist", userAuth.AccountId)
	}

	if _, ok := testAccount.Users[userAuth.UserId]; !ok {
		return userAuth, fmt.Errorf("user with id %s does not exist", userAuth.UserId)
	}

	return userAuth, nil
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

	})

	mockAuth := &auth.MockManager{
		ValidateAndParseTokenFunc:       mockValidateAndParseToken,
		EnsureUserAccessByJWTGroupsFunc: mockEnsureUserAccessByJWTGroups,
		MarkPATUsedFunc:                 mockMarkPATUsed,
		GetPATInfoFunc:                  mockGetAccountInfoFromPAT,
	}

	authMiddleware := NewAuthMiddleware(
		mockAuth,
		func(ctx context.Context, userAuth nbcontext.UserAuth) (string, string, error) {
			return userAuth.AccountId, userAuth.UserId, nil
		},
		func(ctx context.Context, userAuth nbcontext.UserAuth) error {
			return nil
		},
		func(ctx context.Context, userAuth nbcontext.UserAuth) (*types.User, error) {
			return &types.User{}, nil
		},
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

func TestAuthMiddleware_Handler_Child(t *testing.T) {
	tt := []struct {
		name             string
		path             string
		authHeader       string
		expectedUserAuth *nbcontext.UserAuth // nil expects 401 response status
	}{
		{
			name:       "Valid PAT Token",
			path:       "/test",
			authHeader: "Token " + PAT,
			expectedUserAuth: &nbcontext.UserAuth{
				AccountId:      accountID,
				UserId:         userID,
				Domain:         testAccount.Domain,
				DomainCategory: testAccount.DomainCategory,
				IsPAT:          true,
			},
		},
		{
			name:       "Valid PAT Token accesses child",
			path:       "/test?account=xyz",
			authHeader: "Token " + PAT,
			expectedUserAuth: &nbcontext.UserAuth{
				AccountId:      "xyz",
				UserId:         userID,
				Domain:         testAccount.Domain,
				DomainCategory: testAccount.DomainCategory,
				IsChild:        true,
				IsPAT:          true,
			},
		},
		{
			name:       "Valid JWT Token",
			path:       "/test",
			authHeader: "Bearer " + JWT,
			expectedUserAuth: &nbcontext.UserAuth{
				AccountId:      accountID,
				UserId:         userID,
				Domain:         testAccount.Domain,
				DomainCategory: testAccount.DomainCategory,
			},
		},

		{
			name:       "Valid JWT Token with child",
			path:       "/test?account=xyz",
			authHeader: "Bearer " + JWT,
			expectedUserAuth: &nbcontext.UserAuth{
				AccountId:      "xyz",
				UserId:         userID,
				Domain:         testAccount.Domain,
				DomainCategory: testAccount.DomainCategory,
				IsChild:        true,
			},
		},
	}

	mockAuth := &auth.MockManager{
		ValidateAndParseTokenFunc:       mockValidateAndParseToken,
		EnsureUserAccessByJWTGroupsFunc: mockEnsureUserAccessByJWTGroups,
		MarkPATUsedFunc:                 mockMarkPATUsed,
		GetPATInfoFunc:                  mockGetAccountInfoFromPAT,
	}

	authMiddleware := NewAuthMiddleware(
		mockAuth,
		func(ctx context.Context, userAuth nbcontext.UserAuth) (string, string, error) {
			return userAuth.AccountId, userAuth.UserId, nil
		},
		func(ctx context.Context, userAuth nbcontext.UserAuth) error {
			return nil
		},
		func(ctx context.Context, userAuth nbcontext.UserAuth) (*types.User, error) {
			return &types.User{}, nil
		},
	)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			handlerToTest := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userAuth, err := nbcontext.GetUserAuthFromRequest(r)
				if tc.expectedUserAuth != nil {
					assert.NoError(t, err)
					assert.Equal(t, *tc.expectedUserAuth, userAuth)
				} else {
					assert.Error(t, err)
					assert.Empty(t, userAuth)
				}
			}))

			req := httptest.NewRequest("GET", "http://testing"+tc.path, nil)
			req.Header.Set("Authorization", tc.authHeader)
			rec := httptest.NewRecorder()

			handlerToTest.ServeHTTP(rec, req)

			result := rec.Result()
			defer result.Body.Close()

			if tc.expectedUserAuth != nil {
				assert.Equal(t, 200, result.StatusCode)
			} else {
				assert.Equal(t, 401, result.StatusCode)
			}
		})
	}
}
