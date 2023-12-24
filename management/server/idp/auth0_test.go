package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

type mockHTTPClient struct {
	code    int
	resBody string
	reqBody string
	err     error
}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err == nil {
		c.reqBody = string(body)
	}
	return &http.Response{
		StatusCode: c.code,
		Body:       io.NopCloser(strings.NewReader(c.resBody)),
	}, c.err
}

type mockJsonParser struct {
	jsonParser           JsonParser
	marshalErrorString   string
	unmarshalErrorString string
}

func (m *mockJsonParser) Marshal(v interface{}) ([]byte, error) {
	if m.marshalErrorString != "" {
		return nil, fmt.Errorf(m.marshalErrorString)
	}
	return m.jsonParser.Marshal(v)
}

func (m *mockJsonParser) Unmarshal(data []byte, v interface{}) error {
	if m.unmarshalErrorString != "" {
		return fmt.Errorf(m.unmarshalErrorString)
	}
	return m.jsonParser.Unmarshal(data, v)
}

type mockAuth0Credentials struct {
	jwtToken JWTToken
	err      error
}

func (mc *mockAuth0Credentials) Authenticate() (JWTToken, error) {
	return mc.jwtToken, mc.err
}

func newTestJWT(t *testing.T, expInt int) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(expInt) * time.Second).Unix(),
	})
	var hmacSampleSecret []byte
	tokenString, err := token.SignedString(hmacSampleSecret)
	if err != nil {
		t.Fatal(err)
	}
	return tokenString
}

func TestAuth0_RequestJWTToken(t *testing.T) {

	type requestJWTTokenTest struct {
		name                    string
		inputCode               int
		inputResBody            string
		helper                  ManagerHelper
		expectedFuncExitErrDiff error
		expectedCode            int
		expectedToken           string
	}
	exp := 5
	token := newTestJWT(t, exp)

	requestJWTTokenTesttCase1 := requestJWTTokenTest{
		name:          "Get Good JWT Response",
		inputCode:     200,
		inputResBody:  fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		helper:        JsonParser{},
		expectedCode:  200,
		expectedToken: token,
	}
	requestJWTTokenTestCase2 := requestJWTTokenTest{
		name:                    "Request Bad Status Code",
		inputCode:               400,
		inputResBody:            "{}",
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("unable to get token, statusCode 400"),
		expectedCode:            200,
		expectedToken:           "",
	}

	for _, testCase := range []requestJWTTokenTest{requestJWTTokenTesttCase1, requestJWTTokenTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputResBody,
				code:    testCase.inputCode,
			}
			config := Auth0ClientConfig{}

			creds := Auth0Credentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
				helper:       testCase.helper,
			}

			res, err := creds.requestJWTToken()
			if err != nil {
				if testCase.expectedFuncExitErrDiff != nil {
					assert.EqualError(t, err, testCase.expectedFuncExitErrDiff.Error(), "errors should be the same")
				} else {
					t.Fatal(err)
				}
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			assert.NoError(t, err, "unable to read the response body")

			jwtToken := JWTToken{}
			err = json.Unmarshal(body, &jwtToken)
			assert.NoError(t, err, "unable to parse the json input")

			assert.Equalf(t, testCase.expectedToken, jwtToken.AccessToken, "two tokens should be the same")
		})
	}
}

func TestAuth0_ParseRequestJWTResponse(t *testing.T) {
	type parseRequestJWTResponseTest struct {
		name                 string
		inputResBody         string
		helper               ManagerHelper
		expectedToken        string
		expectedExpiresIn    int
		assertErrFunc        func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
		assertErrFuncMessage string
	}

	exp := 100
	token := newTestJWT(t, exp)

	parseRequestJWTResponseTestCase1 := parseRequestJWTResponseTest{
		name:                 "Parse Good JWT Body",
		inputResBody:         fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		helper:               JsonParser{},
		expectedToken:        token,
		expectedExpiresIn:    exp,
		assertErrFunc:        assert.NoError,
		assertErrFuncMessage: "no error was expected",
	}
	parseRequestJWTResponseTestCase2 := parseRequestJWTResponseTest{
		name:                 "Parse Bad json JWT Body",
		inputResBody:         "",
		helper:               JsonParser{},
		expectedToken:        "",
		expectedExpiresIn:    0,
		assertErrFunc:        assert.Error,
		assertErrFuncMessage: "json error was expected",
	}

	for _, testCase := range []parseRequestJWTResponseTest{parseRequestJWTResponseTestCase1, parseRequestJWTResponseTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {

			rawBody := io.NopCloser(strings.NewReader(testCase.inputResBody))

			config := Auth0ClientConfig{}

			creds := Auth0Credentials{
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

func TestAuth0_JwtStillValid(t *testing.T) {

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

			config := Auth0ClientConfig{}

			creds := Auth0Credentials{
				clientConfig: config,
			}
			creds.jwtToken.expiresInTime = testCase.inputTime

			assert.Equalf(t, testCase.expectedResult, creds.jwtStillValid(), testCase.message)
		})
	}
}

func TestAuth0_Authenticate(t *testing.T) {
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
		name:             "Get Cached token",
		inputExpireToken: time.Now().Add(30 * time.Second),
		helper:           JsonParser{},
		// expectedFuncExitErrDiff: fmt.Errorf("unable to get token, statusCode 400"),
		expectedCode:  200,
		expectedToken: "",
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
		expectedFuncExitErrDiff: fmt.Errorf("unable to get token, statusCode 400"),
		expectedCode:            200,
		expectedToken:           "",
	}

	for _, testCase := range []authenticateTest{authenticateTestCase1, authenticateTestCase2, authenticateTestCase3} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputResBody,
				code:    testCase.inputCode,
			}
			config := Auth0ClientConfig{}

			creds := Auth0Credentials{
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

func TestAuth0_UpdateUserAppMetadata(t *testing.T) {

	type updateUserAppMetadataTest struct {
		name                 string
		inputReqBody         string
		expectedReqBody      string
		appMetadata          AppMetadata
		statusCode           int
		helper               ManagerHelper
		managerCreds         ManagerCredentials
		assertErrFunc        func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
		assertErrFuncMessage string
	}

	exp := 15
	token := newTestJWT(t, exp)
	appMetadata := AppMetadata{WTAccountID: "ok"}

	updateUserAppMetadataTestCase1 := updateUserAppMetadataTest{
		name:            "Bad Authentication",
		inputReqBody:    fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		expectedReqBody: "",
		appMetadata:     appMetadata,
		statusCode:      400,
		helper:          JsonParser{},
		managerCreds: &mockAuth0Credentials{
			jwtToken: JWTToken{},
			err:      fmt.Errorf("error"),
		},
		assertErrFunc:        assert.Error,
		assertErrFuncMessage: "should return error",
	}

	updateUserAppMetadataTestCase2 := updateUserAppMetadataTest{
		name:            "Bad Status Code",
		inputReqBody:    fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		expectedReqBody: fmt.Sprintf("{\"app_metadata\":{\"wt_account_id\":\"%s\"}}", appMetadata.WTAccountID),
		appMetadata:     appMetadata,
		statusCode:      400,
		helper:          JsonParser{},
		managerCreds: &mockAuth0Credentials{
			jwtToken: JWTToken{},
		},
		assertErrFunc:        assert.Error,
		assertErrFuncMessage: "should return error",
	}

	updateUserAppMetadataTestCase3 := updateUserAppMetadataTest{
		name:                 "Bad Response Parsing",
		inputReqBody:         fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		statusCode:           400,
		helper:               &mockJsonParser{marshalErrorString: "error"},
		assertErrFunc:        assert.Error,
		assertErrFuncMessage: "should return error",
	}

	updateUserAppMetadataTestCase4 := updateUserAppMetadataTest{
		name:                 "Good request",
		inputReqBody:         fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		expectedReqBody:      fmt.Sprintf("{\"app_metadata\":{\"wt_account_id\":\"%s\"}}", appMetadata.WTAccountID),
		appMetadata:          appMetadata,
		statusCode:           200,
		helper:               JsonParser{},
		assertErrFunc:        assert.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	invite := true
	updateUserAppMetadataTestCase5 := updateUserAppMetadataTest{
		name:            "Update Pending Invite",
		inputReqBody:    fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		expectedReqBody: fmt.Sprintf("{\"app_metadata\":{\"wt_account_id\":\"%s\",\"wt_pending_invite\":true}}", appMetadata.WTAccountID),
		appMetadata: AppMetadata{
			WTAccountID:     "ok",
			WTPendingInvite: &invite,
		},
		statusCode:           200,
		helper:               JsonParser{},
		assertErrFunc:        assert.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	for _, testCase := range []updateUserAppMetadataTest{updateUserAppMetadataTestCase1, updateUserAppMetadataTestCase2,
		updateUserAppMetadataTestCase3, updateUserAppMetadataTestCase4, updateUserAppMetadataTestCase5} {
		t.Run(testCase.name, func(t *testing.T) {
			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputReqBody,
				code:    testCase.statusCode,
			}
			config := Auth0ClientConfig{}

			var creds ManagerCredentials
			if testCase.managerCreds != nil {
				creds = testCase.managerCreds
			} else {
				creds = &Auth0Credentials{
					clientConfig: config,
					httpClient:   &jwtReqClient,
					helper:       testCase.helper,
				}
			}

			manager := Auth0Manager{
				httpClient:  &jwtReqClient,
				credentials: creds,
				helper:      testCase.helper,
			}

			err := manager.UpdateUserAppMetadata("1", testCase.appMetadata)
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)

			assert.Equal(t, testCase.expectedReqBody, jwtReqClient.reqBody, "request body should match")
		})
	}
}

func TestNewAuth0Manager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          Auth0ClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := Auth0ClientConfig{
		AuthIssuer:   "https://abc-auth0.eu.auth0.com",
		Audience:     "https://abc-auth0.eu.auth0.com/api/v2/",
		ClientID:     "abcdefg",
		ClientSecret: "supersecret",
		GrantType:    "client_credentials",
	}

	testCase1 := test{
		name:                 "Good Scenario With Config",
		inputConfig:          defaultTestConfig,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	testCase2Config := defaultTestConfig
	testCase2Config.ClientID = ""

	testCase2 := test{
		name:                 "Missing Configuration",
		inputConfig:          testCase2Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "shouldn't return error when field empty",
	}

	testCase3Config := defaultTestConfig
	testCase3Config.AuthIssuer = "abc-auth0.eu.auth0.com"

	for _, testCase := range []test{testCase1, testCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewAuth0Manager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
		})
	}
}
