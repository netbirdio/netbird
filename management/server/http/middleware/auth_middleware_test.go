package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/auth"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	nbauth "github.com/netbirdio/netbird/shared/auth"
	nbjwt "github.com/netbirdio/netbird/shared/auth/jwt"
)

const (
	audience       = "audience"
	userIDClaim    = "userIDClaim"
	accountID      = "accountID"
	domain         = "domain"
	domainCategory = "domainCategory"
	userID         = "userID"
	tokenID        = "tokenID"
	tokenID2       = "tokenID2"
	PAT            = "nbp_PAT"
	PAT2           = "nbp_PAT2"
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
				tokenID2: {
					ID:             tokenID2,
					Name:           "My second token",
					HashedToken:    "someHash2",
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
	if token == PAT2 {
		return testAccount.Users[userID], testAccount.Users[userID].PATs[tokenID2], testAccount.Domain, testAccount.DomainCategory, nil
	}
	return nil, nil, "", "", fmt.Errorf("PAT invalid")
}

func mockValidateAndParseToken(_ context.Context, token string) (nbauth.UserAuth, *jwt.Token, error) {
	if token == JWT {
		return nbauth.UserAuth{
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
	return nbauth.UserAuth{}, nil, fmt.Errorf("JWT invalid")
}

func mockMarkPATUsed(_ context.Context, token string) error {
	if token == tokenID || token == tokenID2 {
		return nil
	}
	return fmt.Errorf("Should never get reached")
}

func mockEnsureUserAccessByJWTGroups(_ context.Context, userAuth nbauth.UserAuth, token *jwt.Token) (nbauth.UserAuth, error) {
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
		func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
			return userAuth.AccountId, userAuth.UserId, nil
		},
		func(ctx context.Context, userAuth nbauth.UserAuth) error {
			return nil
		},
		func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
			return &types.User{}, nil
		},
		nil,
		nil,
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

func TestAuthMiddleware_RateLimiting(t *testing.T) {
	mockAuth := &auth.MockManager{
		ValidateAndParseTokenFunc:       mockValidateAndParseToken,
		EnsureUserAccessByJWTGroupsFunc: mockEnsureUserAccessByJWTGroups,
		MarkPATUsedFunc:                 mockMarkPATUsed,
		GetPATInfoFunc:                  mockGetAccountInfoFromPAT,
	}

	t.Run("PAT Token Rate Limiting - Burst Works", func(t *testing.T) {
		// Configure rate limiter: 10 requests per minute with burst of 5
		rateLimitConfig := &RateLimiterConfig{
			RequestsPerMinute: 10,
			Burst:             5,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
		}

		authMiddleware := NewAuthMiddleware(
			mockAuth,
			func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
				return userAuth.AccountId, userAuth.UserId, nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) error {
				return nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
				return &types.User{}, nil
			},
			rateLimitConfig,
			nil,
		)

		handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make burst requests - all should succeed
		successCount := 0
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "http://testing/test", nil)
			req.Header.Set("Authorization", "Token "+PAT)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				successCount++
			}
		}

		assert.Equal(t, 5, successCount, "All burst requests should succeed")

		// The 6th request should fail (exceeded burst)
		req := httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Request beyond burst should be rate limited")
	})

	t.Run("PAT Token Rate Limiting - Rate Limit Enforced", func(t *testing.T) {
		// Configure very low rate limit: 1 request per minute
		rateLimitConfig := &RateLimiterConfig{
			RequestsPerMinute: 1,
			Burst:             1,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
		}

		authMiddleware := NewAuthMiddleware(
			mockAuth,
			func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
				return userAuth.AccountId, userAuth.UserId, nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) error {
				return nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
				return &types.User{}, nil
			},
			rateLimitConfig,
			nil,
		)

		handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First request should succeed
		req := httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "First request should succeed")

		// Second request should fail (rate limited)
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Second request should be rate limited")
	})

	t.Run("Bearer Token Not Rate Limited", func(t *testing.T) {
		// Configure strict rate limit
		rateLimitConfig := &RateLimiterConfig{
			RequestsPerMinute: 1,
			Burst:             1,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
		}

		authMiddleware := NewAuthMiddleware(
			mockAuth,
			func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
				return userAuth.AccountId, userAuth.UserId, nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) error {
				return nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
				return &types.User{}, nil
			},
			rateLimitConfig,
			nil,
		)

		handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Make multiple requests with Bearer token - all should succeed
		successCount := 0
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest("GET", "http://testing/test", nil)
			req.Header.Set("Authorization", "Bearer "+JWT)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				successCount++
			}
		}

		assert.Equal(t, 10, successCount, "All Bearer token requests should succeed (not rate limited)")
	})

	t.Run("PAT Token Rate Limiting Per Token", func(t *testing.T) {
		// Configure rate limiter
		rateLimitConfig := &RateLimiterConfig{
			RequestsPerMinute: 1,
			Burst:             1,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
		}

		authMiddleware := NewAuthMiddleware(
			mockAuth,
			func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
				return userAuth.AccountId, userAuth.UserId, nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) error {
				return nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
				return &types.User{}, nil
			},
			rateLimitConfig,
			nil,
		)

		handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Use first PAT token
		req := httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "First request with PAT should succeed")

		// Second request with same token should fail
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Second request with same PAT should be rate limited")

		// Use second PAT token - should succeed because it has independent rate limit
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT2)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "First request with PAT2 should succeed (independent rate limit)")

		// Second request with PAT2 should also be rate limited
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT2)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Second request with PAT2 should be rate limited")

		// JWT should still work (not rate limited)
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Bearer "+JWT)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "JWT request should succeed (not rate limited)")
	})

	t.Run("Rate Limiter Cleanup", func(t *testing.T) {
		// Configure rate limiter with short cleanup interval and TTL for testing
		rateLimitConfig := &RateLimiterConfig{
			RequestsPerMinute: 60,
			Burst:             1,
			CleanupInterval:   100 * time.Millisecond,
			LimiterTTL:        200 * time.Millisecond,
		}

		authMiddleware := NewAuthMiddleware(
			mockAuth,
			func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
				return userAuth.AccountId, userAuth.UserId, nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) error {
				return nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
				return &types.User{}, nil
			},
			rateLimitConfig,
			nil,
		)

		handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First request - should succeed
		req := httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "First request should succeed")

		// Second request immediately - should fail (burst exhausted)
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Second request should be rate limited")

		// Wait for limiter to be cleaned up (TTL + cleanup interval + buffer)
		time.Sleep(400 * time.Millisecond)

		// After cleanup, the limiter should be removed and recreated with full burst capacity
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "Request after cleanup should succeed (new limiter with full burst)")

		// Verify it's a fresh limiter by checking burst is reset
		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Second request after cleanup should be rate limited again")
	})

	t.Run("Terraform User Agent Not Rate Limited", func(t *testing.T) {
		rateLimitConfig := &RateLimiterConfig{
			RequestsPerMinute: 1,
			Burst:             1,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
		}

		authMiddleware := NewAuthMiddleware(
			mockAuth,
			func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
				return userAuth.AccountId, userAuth.UserId, nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) error {
				return nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
				return &types.User{}, nil
			},
			rateLimitConfig,
			nil,
		)

		handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Test various Terraform user agent formats
		terraformUserAgents := []string{
			"Terraform/1.5.0",
			"terraform/1.0.0",
			"Terraform-Provider/2.0.0",
			"Mozilla/5.0 (compatible; Terraform/1.3.0)",
		}

		for _, userAgent := range terraformUserAgents {
			t.Run("UserAgent: "+userAgent, func(t *testing.T) {
				successCount := 0
				for i := 0; i < 10; i++ {
					req := httptest.NewRequest("GET", "http://testing/test", nil)
					req.Header.Set("Authorization", "Token "+PAT)
					req.Header.Set("User-Agent", userAgent)
					rec := httptest.NewRecorder()

					handler.ServeHTTP(rec, req)
					if rec.Code == http.StatusOK {
						successCount++
					}
				}

				assert.Equal(t, 10, successCount, "All Terraform user agent requests should succeed (not rate limited)")
			})
		}
	})

	t.Run("Non-Terraform User Agent With PAT Is Rate Limited", func(t *testing.T) {
		rateLimitConfig := &RateLimiterConfig{
			RequestsPerMinute: 1,
			Burst:             1,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
		}

		authMiddleware := NewAuthMiddleware(
			mockAuth,
			func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
				return userAuth.AccountId, userAuth.UserId, nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) error {
				return nil
			},
			func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
				return &types.User{}, nil
			},
			rateLimitConfig,
			nil,
		)

		handler := authMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		req.Header.Set("User-Agent", "curl/7.68.0")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "First request should succeed")

		req = httptest.NewRequest("GET", "http://testing/test", nil)
		req.Header.Set("Authorization", "Token "+PAT)
		req.Header.Set("User-Agent", "curl/7.68.0")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Second request should be rate limited")
	})
}

func TestAuthMiddleware_Handler_Child(t *testing.T) {
	tt := []struct {
		name             string
		path             string
		authHeader       string
		expectedUserAuth *nbauth.UserAuth // nil expects 401 response status
	}{
		{
			name:       "Valid PAT Token",
			path:       "/test",
			authHeader: "Token " + PAT,
			expectedUserAuth: &nbauth.UserAuth{
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
			expectedUserAuth: &nbauth.UserAuth{
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
			expectedUserAuth: &nbauth.UserAuth{
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
			expectedUserAuth: &nbauth.UserAuth{
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
		func(ctx context.Context, userAuth nbauth.UserAuth) (string, string, error) {
			return userAuth.AccountId, userAuth.UserId, nil
		},
		func(ctx context.Context, userAuth nbauth.UserAuth) error {
			return nil
		},
		func(ctx context.Context, userAuth nbauth.UserAuth) (*types.User, error) {
			return &types.User{}, nil
		},
		nil,
		nil,
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
