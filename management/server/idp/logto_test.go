package idp

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

func TestNewLogtoManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          LogtoClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := LogtoClientConfig{
		ClientID:           "client_id",
		ClientSecret:       "client_secret",
		ManagementEndpoint: "https://localhost:3001/api",
		TokenEndpoint:      "https://localhost:3001/oidc/token",
		Resource:           "https://default.logto.app/api",
		GrantType:          "client_credentials",
		TenantID:           "default",
	}

	testCase1 := test{
		name:                 "Good Configuration",
		inputConfig:          defaultTestConfig,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	testCase2Config := defaultTestConfig
	testCase2Config.ClientID = ""

	testCase2 := test{
		name:                 "Missing ClientID Configuration",
		inputConfig:          testCase2Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	testCase3Config := defaultTestConfig
	testCase3Config.ClientSecret = ""

	testCase3 := test{
		name:                 "Missing ClientSecret Configuration",
		inputConfig:          testCase3Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	testCase4Config := defaultTestConfig
	testCase4Config.TokenEndpoint = ""

	testCase4 := test{
		name:                 "Missing TokenEndpoint Configuration",
		inputConfig:          testCase4Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	testCase5Config := defaultTestConfig
	testCase5Config.ManagementEndpoint = ""

	testCase5 := test{
		name:                 "Missing ManagementEndpoint Configuration",
		inputConfig:          testCase5Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	testCase6Config := defaultTestConfig
	testCase6Config.Resource = ""

	testCase6 := test{
		name:                 "Missing Resource Configuration",
		inputConfig:          testCase6Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	testCase7Config := defaultTestConfig
	testCase7Config.GrantType = ""

	testCase7 := test{
		name:                 "Missing GrantType Configuration",
		inputConfig:          testCase7Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4, testCase5, testCase6, testCase7} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewLogtoManager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
		})
	}
}

func TestLogtoRequestJWTToken(t *testing.T) {
	type requestJWTTokenTest struct {
		name                    string
		inputCode               int
		inputRespBody           string
		helper                  ManagerHelper
		expectedFuncExitErrDiff error
		expectedToken           string
	}
	exp := 5
	token := newTestJWT(t, exp)

	testCase1 := requestJWTTokenTest{
		name:          "Good Token Request",
		inputCode:     200,
		inputRespBody: fmt.Sprintf(`{"access_token":"%s","expires_in":3600,"token_type":"Bearer","scope":"all"}`, token),
		helper:        JsonParser{},
		expectedToken: token,
	}

	testCase2 := requestJWTTokenTest{
		name:                    "Bad Token Request",
		inputCode:               400,
		inputRespBody:           `{"error":"invalid_request"}`,
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("unable to get logto token, statusCode 400"),
	}

	for _, testCase := range []requestJWTTokenTest{testCase1, testCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			config := LogtoClientConfig{
				ClientID:           "client_id",
				ClientSecret:       "client_secret",
				TokenEndpoint:      "https://localhost:3001/oidc/token",
				Resource:           "https://default.logto.app/api",
				GrantType:          "client_credentials",
				ManagementEndpoint: "https://localhost:3001/api",
			}

			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputRespBody,
				code:    testCase.inputCode,
			}

			creds := LogtoCredentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
				helper:       testCase.helper,
			}

			resp, err := creds.requestJWTToken(context.Background())

			if testCase.expectedFuncExitErrDiff != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.expectedFuncExitErrDiff.Error())
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), testCase.expectedToken)
		})
	}
}

func TestLogtoParseRequestJWTResponse(t *testing.T) {
	type parseJWTResponseTest struct {
		name                    string
		inputRespBody           string
		helper                  ManagerHelper
		expectedFuncExitErrDiff error
		expectedToken           string
	}

	exp := 5
	token := newTestJWT(t, exp)

	testCase1 := parseJWTResponseTest{
		name:          "Good Token Response",
		inputRespBody: fmt.Sprintf(`{"access_token":"%s","expires_in":3600,"token_type":"Bearer","scope":"all"}`, token),
		helper:        JsonParser{},
		expectedToken: token,
	}

	testCase2 := parseJWTResponseTest{
		name:                    "Empty Token Response",
		inputRespBody:           `{"access_token":"","expires_in":0}`,
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("error while reading response body"),
	}

	for _, testCase := range []parseJWTResponseTest{testCase1, testCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			config := LogtoClientConfig{}
			creds := LogtoCredentials{
				clientConfig: config,
				helper:       testCase.helper,
							}

			respBody := io.NopCloser(strings.NewReader(testCase.inputRespBody))
			jwtToken, err := creds.parseRequestJWTResponse(respBody)

			if testCase.expectedFuncExitErrDiff != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.expectedFuncExitErrDiff.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.expectedToken, jwtToken.AccessToken)
			assert.Equal(t, 3600, jwtToken.ExpiresIn)
			assert.Equal(t, "Bearer", jwtToken.TokenType)
		})
	}
}

func TestLogtoJwtStillValid(t *testing.T) {
	type jwtStillValidTest struct {
		name           string
		inputToken     JWTToken
		expectedResult bool
	}

	exp := time.Now().Add(10 * time.Minute).Unix()
	token := newTestJWT(t, int(exp))

	testCase1 := jwtStillValidTest{
		name: "Valid Token",
		inputToken: JWTToken{
			AccessToken:   token,
			ExpiresIn:     3600,
			expiresInTime: time.Unix(exp, 0),
		},
		expectedResult: true,
	}

	expired := time.Now().Add(-10 * time.Minute).Unix()
	expiredToken := newTestJWT(t, int(expired))

	testCase2 := jwtStillValidTest{
		name: "Expired Token",
		inputToken: JWTToken{
			AccessToken:   expiredToken,
			ExpiresIn:     3600,
			expiresInTime: time.Unix(expired, 0),
		},
		expectedResult: false,
	}

	testCase3 := jwtStillValidTest{
		name: "Zero Time Token",
		inputToken: JWTToken{
			AccessToken:   token,
			ExpiresIn:     3600,
			expiresInTime: time.Time{},
		},
		expectedResult: false,
	}

	for _, testCase := range []jwtStillValidTest{testCase1, testCase2, testCase3} {
		t.Run(testCase.name, func(t *testing.T) {
			config := LogtoClientConfig{}
			creds := LogtoCredentials{
				clientConfig: config,
				jwtToken:     testCase.inputToken,
							}

			result := creds.jwtStillValid()
			assert.Equal(t, testCase.expectedResult, result)
		})
	}
}

func TestLogtoAuthenticate(t *testing.T) {
	type authenticateTest struct {
		name                    string
		inputCode               int
		inputRespBody           string
		helper                  ManagerHelper
		expectedFuncExitErrDiff error
		expectedToken           string
	}

	exp := 5
	token := newTestJWT(t, exp)

	testCase1 := authenticateTest{
		name:          "Good Authentication",
		inputCode:     200,
		inputRespBody: fmt.Sprintf(`{"access_token":"%s","expires_in":3600,"token_type":"Bearer","scope":"all"}`, token),
		helper:        JsonParser{},
		expectedToken: token,
	}

	testCase2 := authenticateTest{
		name:                    "Bad Authentication",
		inputCode:               400,
		inputRespBody:           `{"error":"invalid_request"}`,
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("unable to get logto token, statusCode 400"),
	}

	for _, testCase := range []authenticateTest{testCase1, testCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			config := LogtoClientConfig{
				ClientID:           "client_id",
				ClientSecret:       "client_secret",
				TokenEndpoint:      "https://localhost:3001/oidc/token",
				Resource:           "https://default.logto.app/api",
				GrantType:          "client_credentials",
				ManagementEndpoint: "https://localhost:3001/api",
			}

			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputRespBody,
				code:    testCase.inputCode,
			}

			creds := LogtoCredentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
				helper:       testCase.helper,
			}

			jwtToken, err := creds.Authenticate(context.Background())

			if testCase.expectedFuncExitErrDiff != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.expectedFuncExitErrDiff.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.expectedToken, jwtToken.AccessToken)
		})
	}
}

func TestLogtoProfile(t *testing.T) {
	type profileTest struct {
		name           string
		inputProfile   logtoProfile
		expectedEmail  string
		expectedName   string
		expectedUserID string
	}

	testCase1 := profileTest{
		name: "Good Profile",
		inputProfile: logtoProfile{
			ID:           "user-123",
			Username:     "testuser",
			PrimaryEmail: "test@example.com",
			Name:         "Test User",
		},
		expectedEmail:  "test@example.com",
		expectedName:   "Test User",
		expectedUserID: "user-123",
	}

	testCase2 := profileTest{
		name: "Profile with Empty Name Falls Back to Username",
		inputProfile: logtoProfile{
			ID:           "user-456",
			Username:     "user456",
			PrimaryEmail: "user456@example.com",
			Name:         "",
		},
		expectedEmail:  "user456@example.com",
		expectedName:   "user456", // Falls back to username when name is empty
		expectedUserID: "user-456",
	}

	for _, testCase := range []profileTest{testCase1, testCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			userData := testCase.inputProfile.userData()
			assert.Equal(t, testCase.expectedEmail, userData.Email)
			assert.Equal(t, testCase.expectedName, userData.Name)
			assert.Equal(t, testCase.expectedUserID, userData.ID)
		})
	}
}
