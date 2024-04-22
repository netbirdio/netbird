package jwtclaims

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
)

func newTestRequestWithJWT(t *testing.T, claims AuthorizationClaims, audience string) *http.Request {
	t.Helper()
	const layout = "2006-01-02T15:04:05.999Z"

	claimMaps := jwt.MapClaims{}
	if claims.UserId != "" {
		claimMaps[UserIDClaim] = claims.UserId
	}
	if claims.AccountId != "" {
		claimMaps[audience+AccountIDSuffix] = claims.AccountId
	}
	if claims.Domain != "" {
		claimMaps[audience+DomainIDSuffix] = claims.Domain
	}
	if claims.DomainCategory != "" {
		claimMaps[audience+DomainCategorySuffix] = claims.DomainCategory
	}
	if claims.LastLogin != (time.Time{}) {
		claimMaps[audience+LastLoginSuffix] = claims.LastLogin.Format(layout)
	}

	if claims.Invited {
		claimMaps[audience+Invited] = true
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimMaps)
	r, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
	require.NoError(t, err, "creating testing request failed")
	testRequest := r.WithContext(context.WithValue(r.Context(), TokenUserProperty, token)) // nolint

	return testRequest
}

func TestExtractClaimsFromRequestContext(t *testing.T) {
	type test struct {
		name                     string
		inputAuthorizationClaims AuthorizationClaims
		inputAudiance            string
		testingFunc              require.ComparisonAssertionFunc
		expectedMSG              string
	}

	const layout = "2006-01-02T15:04:05.999Z"
	lastLogin, _ := time.Parse(layout, "2023-08-17T09:30:40.465Z")

	testCase1 := test{
		name:          "All Claim Fields",
		inputAudiance: "https://login/",
		inputAuthorizationClaims: AuthorizationClaims{
			UserId:         "test",
			Domain:         "test.com",
			AccountId:      "testAcc",
			LastLogin:      lastLogin,
			DomainCategory: "public",
			Invited:        true,
			Raw: jwt.MapClaims{
				"https://login/wt_account_domain":          "test.com",
				"https://login/wt_account_domain_category": "public",
				"https://login/wt_account_id":              "testAcc",
				"https://login/nb_last_login":              lastLogin.Format(layout),
				"sub":                                      "test",
				"https://login/" + Invited:                 true,
			},
		},
		testingFunc: require.EqualValues,
		expectedMSG: "extracted claims should match input claims",
	}

	testCase2 := test{
		name:          "Domain Is Empty",
		inputAudiance: "https://login/",
		inputAuthorizationClaims: AuthorizationClaims{
			UserId:    "test",
			AccountId: "testAcc",
			Raw: jwt.MapClaims{
				"https://login/wt_account_id": "testAcc",
				"sub":                         "test",
			},
		},
		testingFunc: require.EqualValues,
		expectedMSG: "extracted claims should match input claims",
	}

	testCase3 := test{
		name:          "Account ID Is Empty",
		inputAudiance: "https://login/",
		inputAuthorizationClaims: AuthorizationClaims{
			UserId: "test",
			Domain: "test.com",
			Raw: jwt.MapClaims{
				"https://login/wt_account_domain": "test.com",
				"sub":                             "test",
			},
		},
		testingFunc: require.EqualValues,
		expectedMSG: "extracted claims should match input claims",
	}

	testCase4 := test{
		name:          "Category Is Empty",
		inputAudiance: "https://login/",
		inputAuthorizationClaims: AuthorizationClaims{
			UserId:    "test",
			Domain:    "test.com",
			AccountId: "testAcc",
			Raw: jwt.MapClaims{
				"https://login/wt_account_domain": "test.com",
				"https://login/wt_account_id":     "testAcc",
				"sub":                             "test",
			},
		},
		testingFunc: require.EqualValues,
		expectedMSG: "extracted claims should match input claims",
	}

	testCase5 := test{
		name:          "Only User ID Is set",
		inputAudiance: "https://login/",
		inputAuthorizationClaims: AuthorizationClaims{
			UserId: "test",
			Raw: jwt.MapClaims{
				"sub": "test",
			},
		},
		testingFunc: require.EqualValues,
		expectedMSG: "extracted claims should match input claims",
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4, testCase5} {
		t.Run(testCase.name, func(t *testing.T) {
			request := newTestRequestWithJWT(t, testCase.inputAuthorizationClaims, testCase.inputAudiance)

			extractor := NewClaimsExtractor(WithAudience(testCase.inputAudiance))
			extractedClaims := extractor.FromRequestContext(request)

			testCase.testingFunc(t, testCase.inputAuthorizationClaims, extractedClaims, testCase.expectedMSG)
		})
	}
}

func TestExtractClaimsSetOptions(t *testing.T) {
	t.Helper()
	type test struct {
		name      string
		extractor *ClaimsExtractor
		check     func(t *testing.T, c test)
	}

	testCase1 := test{
		name:      "No custom options",
		extractor: NewClaimsExtractor(),
		check: func(t *testing.T, c test) {
			t.Helper()
			if c.extractor.authAudience != "" {
				t.Error("audience should be empty")
				return
			}
			if c.extractor.userIDClaim != UserIDClaim {
				t.Errorf("user id claim should be default, expected %s, got %s", UserIDClaim, c.extractor.userIDClaim)
				return
			}
			if c.extractor.FromRequestContext == nil {
				t.Error("from request context should not be nil")
				return
			}
		},
	}

	testCase2 := test{
		name:      "Custom audience",
		extractor: NewClaimsExtractor(WithAudience("https://login/")),
		check: func(t *testing.T, c test) {
			t.Helper()
			if c.extractor.authAudience != "https://login/" {
				t.Errorf("audience expected %s, got %s", "https://login/", c.extractor.authAudience)
				return
			}
		},
	}

	testCase3 := test{
		name:      "Custom user id claim",
		extractor: NewClaimsExtractor(WithUserIDClaim("customUserId")),
		check: func(t *testing.T, c test) {
			t.Helper()
			if c.extractor.userIDClaim != "customUserId" {
				t.Errorf("user id claim expected %s, got %s", "customUserId", c.extractor.userIDClaim)
				return
			}
		},
	}

	testCase4 := test{
		name: "Custom extractor from request context",
		extractor: NewClaimsExtractor(
			WithFromRequestContext(func(r *http.Request) AuthorizationClaims {
				return AuthorizationClaims{
					UserId: "testCustomRequest",
				}
			})),
		check: func(t *testing.T, c test) {
			t.Helper()
			claims := c.extractor.FromRequestContext(&http.Request{})
			if claims.UserId != "testCustomRequest" {
				t.Errorf("user id claim expected %s, got %s", "testCustomRequest", claims.UserId)
				return
			}
		},
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.check(t, testCase)
		})
	}
}
