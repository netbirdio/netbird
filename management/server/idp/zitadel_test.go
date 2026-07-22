package idp

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
		expectedUseV2API     bool
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
		expectedUseV2API:     false,
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
	testCase4Config.APIVersion = "v2"

	testCase4 := test{
		name:                 "APIVersion v2 enables v2 API",
		inputConfig:          testCase4Config,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
		expectedUseV2API:     true,
	}

	testCase5Config := defaultTestConfig
	testCase5Config.APIVersion = "V2"

	testCase5 := test{
		name:                 "APIVersion v2 is case-insensitive",
		inputConfig:          testCase5Config,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
		expectedUseV2API:     true,
	}

	testCase6Config := ZitadelClientConfig{
		ManagementEndpoint: "http://localhost/management/v1",
		PAT:                "my-personal-access-token",
	}

	testCase6 := test{
		name:                 "PAT configuration skips JWT validation",
		inputConfig:          testCase6Config,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error with PAT",
		expectedUseV2API:     false,
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4, testCase5, testCase6} {
		t.Run(testCase.name, func(t *testing.T) {
			manager, err := NewZitadelManager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
			if err == nil {
				assert.Equal(t, testCase.expectedUseV2API, manager.useV2API, "useV2API should match expected value")
			}
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
		inputRespBody:           "{\"error\": \"invalid_scope\", \"error_description\":\"openid missing\"}",
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("unable to get zitadel token, statusCode 400, zitadel: error: invalid_scope error_description: openid missing"),
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

			resp, err := creds.requestJWTToken(context.Background())
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
		inputRespBody:        "{}",
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
		expectedFuncExitErrDiff: fmt.Errorf("unable to get zitadel token, statusCode 400, zitadel: unknown error"),
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

			_, err := creds.Authenticate(context.Background())
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

// newZitadelManagerWithMock builds a ZitadelManager wired to a pre-authenticated mock HTTP client,
// bypassing NewZitadelManager so tests can control useV2API directly.
func newZitadelManagerWithMock(useV2API bool, httpClient *mockHTTPClient) *ZitadelManager {
	exp := 100
	creds := &ZitadelCredentials{
		clientConfig: ZitadelClientConfig{},
		httpClient:   httpClient,
		helper:       JsonParser{},
	}
	creds.jwtToken.AccessToken = "test-token"
	creds.jwtToken.expiresInTime = time.Now().Add(time.Duration(exp) * time.Second)

	return &ZitadelManager{
		managementEndpoint: "http://localhost/v2",
		httpClient:         httpClient,
		credentials:        creds,
		helper:             JsonParser{},
		useV2API:           useV2API,
	}
}

func TestZitadelCreateUser_v2_RequestBody(t *testing.T) {
	client := &mockHTTPClient{
		code:    201,
		resBody: `{"userId":"new-user-id-v2"}`,
	}
	manager := newZitadelManagerWithMock(true, client)

	_, err := manager.CreateUser(context.Background(), "alice@example.com", "Alice Smith", "acc1", "inviter@example.com")
	require.NoError(t, err)

	assert.Contains(t, client.reqBody, `"username"`, "v2 API must use \"username\" field")
	assert.NotContains(t, client.reqBody, `"userName"`, "v2 API must not use \"userName\" field")
	assert.Contains(t, client.reqBody, `"givenName"`, "v2 API must use \"givenName\" in profile")
	assert.Contains(t, client.reqBody, `"familyName"`, "v2 API must use \"familyName\" in profile")
	assert.Contains(t, client.reqBody, `"isVerified"`, "v2 API must use \"isVerified\" in email")
}

func TestZitadelCreateUser_v1_RequestBody(t *testing.T) {
	client := &mockHTTPClient{
		code:    200,
		resBody: `{"userId":"new-user-id-v1"}`,
	}
	manager := newZitadelManagerWithMock(false, client)

	_, err := manager.CreateUser(context.Background(), "alice@example.com", "Alice Smith", "acc1", "inviter@example.com")
	require.NoError(t, err)

	assert.Contains(t, client.reqBody, `"userName"`, "v1 API must use \"userName\" field")
	assert.NotContains(t, client.reqBody, `"username"`, "v1 API must not use \"username\" field")
	assert.Contains(t, client.reqBody, `"firstName"`, "v1 API must use \"firstName\" in profile")
	assert.Contains(t, client.reqBody, `"lastName"`, "v1 API must use \"lastName\" in profile")
	assert.Contains(t, client.reqBody, `"isEmailVerified"`, "v1 API must use \"isEmailVerified\" in email")
}

func TestZitadelInviteUser_v2_Endpoint(t *testing.T) {
	var capturedURL string
	client := &mockHTTPClient{
		code:    200,
		resBody: `{}`,
	}
	manager := newZitadelManagerWithMock(true, client)

	// Intercept the HTTP request to capture the URL
	origClient := manager.httpClient
	manager.httpClient = &captureURLClient{inner: origClient, capturedURL: &capturedURL}

	err := manager.InviteUserByID(context.Background(), "user-abc-123")
	require.NoError(t, err)

	assert.Contains(t, capturedURL, "users/user-abc-123/invite_code", "v2 must use CreateInviteCode endpoint")
	assert.NotContains(t, capturedURL, "invite_code/resend", "v2 must not use deprecated ResendInviteCode endpoint")
	assert.Equal(t, `{"sendCode":{}}`, client.reqBody, "v2 invite must include sendCode variant")
}

func TestZitadelGetAccount_v2_RequestBody(t *testing.T) {
	client := &mockHTTPClient{
		code:    200,
		resBody: `{"result":[]}`,
	}
	manager := newZitadelManagerWithMock(true, client)

	_, err := manager.GetAccount(context.Background(), "acc1")
	require.NoError(t, err)

	assert.Equal(t, "{}", client.reqBody, "v2 search must send \"{}\" body, not empty string")
}

func TestZitadelGetAllAccounts_v2_RequestBody(t *testing.T) {
	client := &mockHTTPClient{
		code:    200,
		resBody: `{"result":[]}`,
	}
	manager := newZitadelManagerWithMock(true, client)

	_, err := manager.GetAllAccounts(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "{}", client.reqBody, "v2 search must send \"{}\" body, not empty string")
}

// captureURLClient wraps a ManagerHTTPClient to capture the request URL.
type captureURLClient struct {
	inner       ManagerHTTPClient
	capturedURL *string
}

func (c *captureURLClient) Do(req *http.Request) (*http.Response, error) {
	*c.capturedURL = req.URL.String()
	return c.inner.Do(req)
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

	// v2 API response: uses userId instead of id, givenName/familyName instead of firstName/lastName
	azureProfileTestCase3 := azureProfileTest{
		name:   "V2 User Request",
		invite: false,
		inputProfile: zitadelProfile{
			UserID:             "test3-v2",
			ID:                 "", // v2 does not populate id
			State:              "USER_STATE_ACTIVE",
			UserName:           "test3@mail.com",
			PreferredLoginName: "test3@mail.com",
			LoginNames: []string{
				"test3@mail.com",
			},
			Human: &zitadelUser{
				Profile: zitadelUserInfo{
					GivenName:   "Alice",
					FamilyName:  "Smith",
					DisplayName: "Alice Smith",
				},
				Email: zitadelEmail{
					Email:      "test3@mail.com",
					IsVerified: true,
				},
			},
		},
		expectedUserData: UserData{
			ID:    "test3-v2",
			Name:  "Alice Smith",
			Email: "test3@mail.com",
			AppMetadata: AppMetadata{
				WTAccountID: "1",
			},
		},
	}

	for _, testCase := range []azureProfileTest{azureProfileTestCase1, azureProfileTestCase2, azureProfileTestCase3} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.expectedUserData.AppMetadata.WTPendingInvite = &testCase.invite
			userData := testCase.inputProfile.userData()

			assert.Equal(t, testCase.expectedUserData.ID, userData.ID, "User id should match")
			assert.Equal(t, testCase.expectedUserData.Email, userData.Email, "User email should match")
			assert.Equal(t, testCase.expectedUserData.Name, userData.Name, "User name should match")
		})
	}
}
