package idp

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

func TestNewZitadelManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          ZitadelClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := ZitadelClientConfig{
		ClientID:           "client_id",
		ClientSecret:       "client_secret",
		GrantType:          "client_credentials",
		TokenEndpoint:      "http://localhost/oauth/v2/token",
		ManagementEndpoint: "http://localhost/management/v1",
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

	for _, testCase := range []test{testCase1, testCase2, testCase3} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewZitadelManager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
		})
	}
}

func TestZitadelRequestJWTToken(t *testing.T) {

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

	requestJWTTokenTesttCase1 := requestJWTTokenTest{
		name:          "Good JWT Response",
		inputCode:     200,
		inputRespBody: fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		helper:        JsonParser{},
		expectedToken: token,
	}
	requestJWTTokenTestCase2 := requestJWTTokenTest{
		name:                    "Request Bad Status Code",
		inputCode:               400,
		inputRespBody:           "{}",
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("unable to get zitadel token, statusCode 400"),
		expectedToken:           "",
	}

	for _, testCase := range []requestJWTTokenTest{requestJWTTokenTesttCase1, requestJWTTokenTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputRespBody,
				code:    testCase.inputCode,
			}
			config := ZitadelClientConfig{}

			creds := ZitadelCredentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
				helper:       testCase.helper,
			}

			resp, err := creds.requestJWTToken()
			if err != nil {
				if testCase.expectedFuncExitErrDiff != nil {
					assert.EqualError(t, err, testCase.expectedFuncExitErrDiff.Error(), "errors should be the same")
				} else {
					t.Fatal(err)
				}
			} else {
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				assert.NoError(t, err, "unable to read the response body")

				jwtToken := JWTToken{}
				err = testCase.helper.Unmarshal(body, &jwtToken)
				assert.NoError(t, err, "unable to parse the json input")

				assert.Equalf(t, testCase.expectedToken, jwtToken.AccessToken, "two tokens should be the same")
			}
		})
	}
}

func TestZitadelParseRequestJWTResponse(t *testing.T) {
	type parseRequestJWTResponseTest struct {
		name                 string
		inputRespBody        string
		helper               ManagerHelper
		expectedToken        string
		expectedExpiresIn    int
		assertErrFunc        assert.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	exp := 100
	token := newTestJWT(t, exp)

	parseRequestJWTResponseTestCase1 := parseRequestJWTResponseTest{
		name:                 "Parse Good JWT Body",
		inputRespBody:        fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		helper:               JsonParser{},
		expectedToken:        token,
		expectedExpiresIn:    exp,
		assertErrFunc:        assert.NoError,
		assertErrFuncMessage: "no error was expected",
	}
	parseRequestJWTResponseTestCase2 := parseRequestJWTResponseTest{
		name:                 "Parse Bad json JWT Body",
		inputRespBody:        "",
		helper:               JsonParser{},
		expectedToken:        "",
		expectedExpiresIn:    0,
		assertErrFunc:        assert.Error,
		assertErrFuncMessage: "json error was expected",
	}

	for _, testCase := range []parseRequestJWTResponseTest{parseRequestJWTResponseTestCase1, parseRequestJWTResponseTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			rawBody := io.NopCloser(strings.NewReader(testCase.inputRespBody))
			config := ZitadelClientConfig{}

			creds := ZitadelCredentials{
				clientConfig: config,
				helper:       testCase.helper,
			}
			jwtToken, err := creds.parseRequestJWTResponse(rawBody)
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)

			assert.Equalf(t, testCase.expectedToken, jwtToken.AccessToken, "two tokens should be the same")
			assert.Equalf(t, testCase.expectedExpiresIn, jwtToken.ExpiresIn, "the two expire times should be the same")
		})
	}
}

func TestZitadelJwtStillValid(t *testing.T) {
	type jwtStillValidTest struct {
		name           string
		inputTime      time.Time
		expectedResult bool
		message        string
	}

	jwtStillValidTestCase1 := jwtStillValidTest{
		name:           "JWT still valid",
		inputTime:      time.Now().Add(10 * time.Second),
		expectedResult: true,
		message:        "should be true",
	}
	jwtStillValidTestCase2 := jwtStillValidTest{
		name:           "JWT is invalid",
		inputTime:      time.Now(),
		expectedResult: false,
		message:        "should be false",
	}

	for _, testCase := range []jwtStillValidTest{jwtStillValidTestCase1, jwtStillValidTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			config := ZitadelClientConfig{}

			creds := ZitadelCredentials{
				clientConfig: config,
			}
			creds.jwtToken.expiresInTime = testCase.inputTime

			assert.Equalf(t, testCase.expectedResult, creds.jwtStillValid(), testCase.message)
		})
	}
}

func TestZitadelAuthenticate(t *testing.T) {
	type authenticateTest struct {
		name                    string
		inputCode               int
		inputResBody            string
		inputExpireToken        time.Time
		helper                  ManagerHelper
		expectedFuncExitErrDiff error
		expectedCode            int
		expectedToken           string
	}
	exp := 5
	token := newTestJWT(t, exp)

	authenticateTestCase1 := authenticateTest{
		name:                    "Get Cached token",
		inputExpireToken:        time.Now().Add(30 * time.Second),
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: nil,
		expectedCode:            200,
		expectedToken:           "",
	}

	authenticateTestCase2 := authenticateTest{
		name:          "Get Good JWT Response",
		inputCode:     200,
		inputResBody:  fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		helper:        JsonParser{},
		expectedCode:  200,
		expectedToken: token,
	}

	authenticateTestCase3 := authenticateTest{
		name:                    "Get Bad Status Code",
		inputCode:               400,
		inputResBody:            "{}",
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("unable to get zitadel token, statusCode 400"),
		expectedCode:            200,
		expectedToken:           "",
	}

	for _, testCase := range []authenticateTest{authenticateTestCase1, authenticateTestCase2, authenticateTestCase3} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputResBody,
				code:    testCase.inputCode,
			}
			config := ZitadelClientConfig{}

			creds := ZitadelCredentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
				helper:       testCase.helper,
			}
			creds.jwtToken.expiresInTime = testCase.inputExpireToken

			_, err := creds.Authenticate()
			if err != nil {
				if testCase.expectedFuncExitErrDiff != nil {
					assert.EqualError(t, err, testCase.expectedFuncExitErrDiff.Error(), "errors should be the same")
				} else {
					t.Fatal(err)
				}
			}

			assert.Equalf(t, testCase.expectedToken, creds.jwtToken.AccessToken, "two tokens should be the same")
		})
	}
}

func TestZitadelProfile(t *testing.T) {
	type azureProfileTest struct {
		name             string
		invite           bool
		inputProfile     zitadelProfile
		expectedUserData UserData
	}

	azureProfileTestCase1 := azureProfileTest{
		name:   "User Request",
		invite: false,
		inputProfile: zitadelProfile{
			ID:                 "test1",
			State:              "USER_STATE_ACTIVE",
			UserName:           "test1@mail.com",
			PreferredLoginName: "test1@mail.com",
			LoginNames: []string{
				"test1@mail.com",
			},
			Human: &zitadelUser{
				Profile: zitadelUserInfo{
					FirstName:   "ZITADEL",
					LastName:    "Admin",
					DisplayName: "ZITADEL Admin",
				},
				Email: zitadelEmail{
					Email:           "test1@mail.com",
					IsEmailVerified: true,
				},
			},
		},
		expectedUserData: UserData{
			ID:    "test1",
			Name:  "ZITADEL Admin",
			Email: "test1@mail.com",
			AppMetadata: AppMetadata{
				WTAccountID: "1",
			},
		},
	}

	azureProfileTestCase2 := azureProfileTest{
		name:   "Service User Request",
		invite: true,
		inputProfile: zitadelProfile{
			ID:                 "test2",
			State:              "USER_STATE_ACTIVE",
			UserName:           "machine",
			PreferredLoginName: "machine",
			LoginNames: []string{
				"machine",
			},
			Human: nil,
		},
		expectedUserData: UserData{
			ID:    "test2",
			Name:  "machine",
			Email: "machine",
			AppMetadata: AppMetadata{
				WTAccountID: "1",
			},
		},
	}

	for _, testCase := range []azureProfileTest{azureProfileTestCase1, azureProfileTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.expectedUserData.AppMetadata.WTPendingInvite = &testCase.invite
			userData := testCase.inputProfile.userData()

			assert.Equal(t, testCase.expectedUserData.ID, userData.ID, "User id should match")
			assert.Equal(t, testCase.expectedUserData.Email, userData.Email, "User email should match")
			assert.Equal(t, testCase.expectedUserData.Name, userData.Name, "User name should match")
		})
	}
}
