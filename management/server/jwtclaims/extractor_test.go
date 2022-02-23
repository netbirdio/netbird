package jwtclaims

import (
	"context"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func newTestRequestWithJWT(t *testing.T, claims AuthorizationClaims, audiance string) *http.Request {
	claimMaps := jwt.MapClaims{}
	if claims.UserId != "" {
		claimMaps[UserIDClaim] = claims.UserId
	}
	if claims.AccountId != "" {
		claimMaps[audiance+AccountIDSuffix] = claims.AccountId
	}
	if claims.Domain != "" {
		claimMaps[audiance+DomainIDSuffix] = claims.Domain
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimMaps)
	r, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
	require.NoError(t, err, "creating testing request failed")
	testRequest := r.WithContext(context.WithValue(r.Context(), TokenUserProperty, token)) //nolint

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

	testCase1 := test{
		name:          "All Claim Fields",
		inputAudiance: "https://login/",
		inputAuthorizationClaims: AuthorizationClaims{
			UserId:    "test",
			Domain:    "test.com",
			AccountId: "testAcc",
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
		},
		testingFunc: require.EqualValues,
		expectedMSG: "extracted claims should match input claims",
	}

	testCase4 := test{
		name:          "Only User ID Is set",
		inputAudiance: "https://login/",
		inputAuthorizationClaims: AuthorizationClaims{
			UserId: "test",
		},
		testingFunc: require.EqualValues,
		expectedMSG: "extracted claims should match input claims",
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4} {
		t.Run(testCase.name, func(t *testing.T) {

			request := newTestRequestWithJWT(t, testCase.inputAuthorizationClaims, testCase.inputAudiance)

			extractedClaims := ExtractClaimsFromRequestContext(request, testCase.inputAudiance)

			testCase.testingFunc(t, testCase.inputAuthorizationClaims, extractedClaims, testCase.expectedMSG)
		})
	}
}
