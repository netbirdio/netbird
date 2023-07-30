package auth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type mockHTTPClient struct {
	code         int
	resBody      string
	reqBody      string
	MaxReqs      int
	count        int
	countResBody string
	err          error
}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err == nil {
		c.reqBody = string(body)
	}

	if c.MaxReqs > c.count {
		c.count++
		return &http.Response{
			StatusCode: c.code,
			Body:       io.NopCloser(strings.NewReader(c.countResBody)),
		}, c.err
	}

	return &http.Response{
		StatusCode: c.code,
		Body:       io.NopCloser(strings.NewReader(c.resBody)),
	}, c.err
}

func TestHosted_RequestDeviceCode(t *testing.T) {
	type test struct {
		name             string
		inputResBody     string
		inputReqCode     int
		inputReqError    error
		testingErrFunc   require.ErrorAssertionFunc
		expectedErrorMSG string
		testingFunc      require.ComparisonAssertionFunc
		expectedOut      AuthFlowInfo
		expectedMSG      string
		expectPayload    string
	}

	expectedAudience := "ok"
	expectedClientID := "bla"
	expectedScope := "openid"
	form := url.Values{}
	form.Add("audience", expectedAudience)
	form.Add("client_id", expectedClientID)
	form.Add("scope", expectedScope)
	expectPayload := form.Encode()

	testCase1 := test{
		name:           "Payload Is Valid",
		expectPayload:  expectPayload,
		inputReqCode:   200,
		testingErrFunc: require.Error,
		testingFunc:    require.EqualValues,
	}

	testCase2 := test{
		name:             "Exit On Network Error",
		inputReqError:    fmt.Errorf("error"),
		testingErrFunc:   require.Error,
		expectedErrorMSG: "should return error",
		testingFunc:      require.EqualValues,
		expectPayload:    expectPayload,
	}

	testCase3 := test{
		name:             "Exit On Exit Code",
		inputReqCode:     400,
		testingErrFunc:   require.Error,
		expectedErrorMSG: "should return error",
		testingFunc:      require.EqualValues,
		expectPayload:    expectPayload,
	}
	testCase4Out := AuthFlowInfo{ExpiresIn: 10}
	testCase4 := test{
		name:           "Got Device Code",
		inputResBody:   fmt.Sprintf("{\"expires_in\":%d}", testCase4Out.ExpiresIn),
		expectPayload:  expectPayload,
		inputReqCode:   200,
		testingErrFunc: require.NoError,
		testingFunc:    require.EqualValues,
		expectedOut:    testCase4Out,
		expectedMSG:    "out should match",
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4} {
		t.Run(testCase.name, func(t *testing.T) {

			httpClient := mockHTTPClient{
				resBody: testCase.inputResBody,
				code:    testCase.inputReqCode,
				err:     testCase.inputReqError,
			}

			deviceFlow := &DeviceAuthorizationFlow{
				providerConfig: internal.DeviceAuthProviderConfig{
					Audience:           expectedAudience,
					ClientID:           expectedClientID,
					Scope:              expectedScope,
					TokenEndpoint:      "test.hosted.com/token",
					DeviceAuthEndpoint: "test.hosted.com/device/auth",
					UseIDToken:         false,
				},
				HTTPClient: &httpClient,
			}

			authInfo, err := deviceFlow.RequestAuthInfo(context.TODO())
			testCase.testingErrFunc(t, err, testCase.expectedErrorMSG)

			require.EqualValues(t, expectPayload, httpClient.reqBody, "payload should match")

			testCase.testingFunc(t, testCase.expectedOut, authInfo, testCase.expectedMSG)

		})
	}
}

func TestHosted_WaitToken(t *testing.T) {
	type test struct {
		name              string
		inputResBody      string
		inputReqCode      int
		inputReqError     error
		inputMaxReqs      int
		inputCountResBody string
		inputTimeout      time.Duration
		inputInfo         AuthFlowInfo
		inputAudience     string
		testingErrFunc    require.ErrorAssertionFunc
		expectedErrorMSG  string
		testingFunc       require.ComparisonAssertionFunc
		expectedOut       TokenInfo
		expectedMSG       string
		expectPayload     string
	}

	defaultInfo := AuthFlowInfo{
		DeviceCode: "test",
		ExpiresIn:  10,
		Interval:   1,
	}

	clientID := "test"

	form := url.Values{}
	form.Add("grant_type", HostedGrantType)
	form.Add("device_code", defaultInfo.DeviceCode)
	form.Add("client_id", clientID)
	tokenReqPayload := form.Encode()

	testCase1 := test{
		name:           "Payload Is Valid",
		inputInfo:      defaultInfo,
		inputTimeout:   time.Duration(defaultInfo.ExpiresIn) * time.Second,
		inputReqCode:   200,
		testingErrFunc: require.Error,
		testingFunc:    require.EqualValues,
		expectPayload:  tokenReqPayload,
	}

	testCase2 := test{
		name:             "Exit On Network Error",
		inputInfo:        defaultInfo,
		inputTimeout:     time.Duration(defaultInfo.ExpiresIn) * time.Second,
		expectPayload:    tokenReqPayload,
		inputReqError:    fmt.Errorf("error"),
		testingErrFunc:   require.Error,
		expectedErrorMSG: "should return error",
		testingFunc:      require.EqualValues,
	}

	testCase3 := test{
		name:             "Exit On 4XX When Not Pending",
		inputInfo:        defaultInfo,
		inputTimeout:     time.Duration(defaultInfo.ExpiresIn) * time.Second,
		inputReqCode:     400,
		expectPayload:    tokenReqPayload,
		testingErrFunc:   require.Error,
		expectedErrorMSG: "should return error",
		testingFunc:      require.EqualValues,
	}

	testCase4 := test{
		name:             "Exit On Exit Code 5XX",
		inputInfo:        defaultInfo,
		inputTimeout:     time.Duration(defaultInfo.ExpiresIn) * time.Second,
		inputReqCode:     500,
		expectPayload:    tokenReqPayload,
		testingErrFunc:   require.Error,
		expectedErrorMSG: "should return error",
		testingFunc:      require.EqualValues,
	}

	testCase5 := test{
		name:             "Exit On Content Timeout",
		inputInfo:        defaultInfo,
		inputTimeout:     0 * time.Second,
		testingErrFunc:   require.Error,
		expectedErrorMSG: "should return error",
		testingFunc:      require.EqualValues,
	}

	audience := "test"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"aud": audience})
	var hmacSampleSecret []byte
	tokenString, _ := token.SignedString(hmacSampleSecret)

	testCase6 := test{
		name:           "Exit On Invalid Audience",
		inputInfo:      defaultInfo,
		inputResBody:   fmt.Sprintf("{\"access_token\":\"%s\"}", tokenString),
		inputTimeout:   time.Duration(defaultInfo.ExpiresIn) * time.Second,
		inputReqCode:   200,
		inputAudience:  "super test",
		testingErrFunc: require.Error,
		testingFunc:    require.EqualValues,
		expectPayload:  tokenReqPayload,
	}

	testCase7 := test{
		name:           "Received Token Info",
		inputInfo:      defaultInfo,
		inputResBody:   fmt.Sprintf("{\"access_token\":\"%s\"}", tokenString),
		inputTimeout:   time.Duration(defaultInfo.ExpiresIn) * time.Second,
		inputReqCode:   200,
		inputAudience:  audience,
		testingErrFunc: require.NoError,
		testingFunc:    require.EqualValues,
		expectPayload:  tokenReqPayload,
		expectedOut:    TokenInfo{AccessToken: tokenString},
	}

	testCase8 := test{
		name:              "Received Token Info after Multiple tries",
		inputInfo:         defaultInfo,
		inputResBody:      fmt.Sprintf("{\"access_token\":\"%s\"}", tokenString),
		inputTimeout:      time.Duration(defaultInfo.ExpiresIn) * time.Second,
		inputMaxReqs:      2,
		inputCountResBody: "{\"error\":\"authorization_pending\"}",
		inputReqCode:      200,
		inputAudience:     audience,
		testingErrFunc:    require.NoError,
		testingFunc:       require.EqualValues,
		expectPayload:     tokenReqPayload,
		expectedOut:       TokenInfo{AccessToken: tokenString},
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4, testCase5, testCase6, testCase7, testCase8} {
		t.Run(testCase.name, func(t *testing.T) {

			httpClient := mockHTTPClient{
				resBody:      testCase.inputResBody,
				code:         testCase.inputReqCode,
				err:          testCase.inputReqError,
				MaxReqs:      testCase.inputMaxReqs,
				countResBody: testCase.inputCountResBody,
			}

			deviceFlow := DeviceAuthorizationFlow{
				providerConfig: internal.DeviceAuthProviderConfig{
					Audience:           testCase.inputAudience,
					ClientID:           clientID,
					TokenEndpoint:      "test.hosted.com/token",
					DeviceAuthEndpoint: "test.hosted.com/device/auth",
					Scope:              "openid",
					UseIDToken:         false,
				},
				HTTPClient: &httpClient,
			}

			ctx, cancel := context.WithTimeout(context.TODO(), testCase.inputTimeout)
			defer cancel()
			tokenInfo, err := deviceFlow.WaitToken(ctx, testCase.inputInfo)
			testCase.testingErrFunc(t, err, testCase.expectedErrorMSG)

			require.EqualValues(t, testCase.expectPayload, httpClient.reqBody, "payload should match")

			testCase.testingFunc(t, testCase.expectedOut, tokenInfo, testCase.expectedMSG)

			require.GreaterOrEqualf(t, testCase.inputMaxReqs, httpClient.count, "should run %d times", testCase.inputMaxReqs)

		})
	}
}
