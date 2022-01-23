package idpmanager

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

type testHTTPClient struct {
	code    int
	resBody string
	reqBody string
	err     error
}

func (c *testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	body, err := ioutil.ReadAll(req.Body)
	if err == nil {
		c.reqBody = string(body)
	}
	return &http.Response{
		StatusCode: c.code,
		Body:       ioutil.NopCloser(strings.NewReader(c.resBody)),
	}, c.err
}

func newTestJWT(t *testing.T, expInt int) string {
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

func TestAuth0_GetJWTToken(t *testing.T) {

	type jwtRequestTest struct {
		name                    string
		inputCode               int
		inputResBody            string
		expectedFuncExitErrDiff error
		expectedCode            int
		expectedToken           string
	}
	exp := 5
	token := newTestJWT(t, exp)

	jwtRequestTestCase1 := jwtRequestTest{
		name:         "Get Good JWT Response",
		inputCode:    200,
		inputResBody: fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		//expectedFuncExitErrDiff: nil,
		expectedCode:  200,
		expectedToken: token,
	}
	jwtRequestTestCase2 := jwtRequestTest{
		name:                    "Request Bad Status Code",
		inputCode:               400,
		inputResBody:            "{}",
		expectedFuncExitErrDiff: fmt.Errorf("unable to get token, statusCode 400"),
		expectedCode:            200,
		expectedToken:           "",
	}

	for _, testCase := range []jwtRequestTest{jwtRequestTestCase1, jwtRequestTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := testHTTPClient{
				resBody: testCase.inputResBody,
				code:    testCase.inputCode,
			}
			config := Auth0ClientConfig{}

			creds := Auth0Credentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
			}

			res, err := creds.getJWTRequest()
			if err != nil {
				if testCase.expectedFuncExitErrDiff != nil {
					assert.EqualError(t, err, testCase.expectedFuncExitErrDiff.Error(), "errors should be the same")
				} else {
					t.Fatal(err)
				}
			}
			body, err := ioutil.ReadAll(res.Body)
			assert.NoError(t, err, "unable to read the response body")

			jwtToken := JWTToken{}
			err = json.Unmarshal(body, &jwtToken)
			assert.NoError(t, err, "unable to parse the json input")

			assert.Equalf(t, testCase.expectedToken, jwtToken.AccessToken, "two tokens should be the same")
		})
	}

	type jwtParseResponseTest struct {
		name                 string
		inputResBody         string
		expectedToken        string
		expectedExpiresIn    int
		assertErrFunc        func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
		assertErrFuncMessage string
	}

	exp = 100
	token = newTestJWT(t, exp)

	jwtParseResponseTestCase1 := jwtParseResponseTest{
		name:                 "Parse Good JWT Body",
		inputResBody:         fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		expectedToken:        token,
		expectedExpiresIn:    exp,
		assertErrFunc:        assert.NoError,
		assertErrFuncMessage: "no error was expected",
	}
	jwtParseResponseTestCase2 := jwtParseResponseTest{
		name:                 "Parse Bad json JWT Body",
		inputResBody:         "",
		expectedToken:        "",
		expectedExpiresIn:    0,
		assertErrFunc:        assert.Error,
		assertErrFuncMessage: "json error was expected",
	}

	for _, testCase := range []jwtParseResponseTest{jwtParseResponseTestCase1, jwtParseResponseTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {

			rawBody := ioutil.NopCloser(strings.NewReader(testCase.inputResBody))

			config := Auth0ClientConfig{}

			creds := Auth0Credentials{
				clientConfig: config,
			}

			jwtToken, err := creds.parseGetJWTResponse(rawBody)
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)

			assert.Equalf(t, testCase.expectedToken, jwtToken.AccessToken, "two tokens should be the same")
			assert.Equalf(t, testCase.expectedExpiresIn, jwtToken.ExpiresIn, "the two expire times should be the same")
		})
	}

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

	type getJWTTokenTest struct {
		name                    string
		inputCode               int
		inputResBody            string
		inputExpireToken        time.Time
		expectedFuncExitErrDiff error
		expectedCode            int
		expectedToken           string
	}
	exp = 5
	token = newTestJWT(t, exp)

	getJWTTokenTestCase1 := getJWTTokenTest{
		name:             "Get Cached token",
		inputExpireToken: time.Now().Add(30 * time.Second),
		//expectedFuncExitErrDiff: fmt.Errorf("unable to get token, statusCode 400"),
		expectedCode:  200,
		expectedToken: "",
	}

	getJWTTokenTestCase2 := getJWTTokenTest{
		name:          "Get Good JWT Response",
		inputCode:     200,
		inputResBody:  fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		expectedCode:  200,
		expectedToken: token,
	}
	getJWTTokenTestCase3 := getJWTTokenTest{
		name:                    "Get Bad Status Code",
		inputCode:               400,
		inputResBody:            "{}",
		expectedFuncExitErrDiff: fmt.Errorf("unable to get token, statusCode 400"),
		expectedCode:            200,
		expectedToken:           "",
	}

	for _, testCase := range []getJWTTokenTest{getJWTTokenTestCase1, getJWTTokenTestCase2, getJWTTokenTestCase3} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := testHTTPClient{
				resBody: testCase.inputResBody,
				code:    testCase.inputCode,
			}
			config := Auth0ClientConfig{}

			creds := Auth0Credentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
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

func Test_UpdateUserAppMetadata(t *testing.T) {

	exp := 5
	token := newTestJWT(t, exp)

	jwtReqClient := testHTTPClient{
		resBody: fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		code:    200,
	}
	config := Auth0ClientConfig{}

	creds := Auth0Credentials{
		clientConfig: config,
		httpClient:   &jwtReqClient,
	}
	manager := Auth0Manager{
		httpClient:  &jwtReqClient,
		credentials: &creds,
	}

	appMetadata := AppMetadata{WTAccountId: "ok"}
	err := manager.UpdateUserAppMetadata("1", appMetadata)
	assert.NoError(t, err, "should be nil")

	expectedReqBody := fmt.Sprintf("{\"app_metadata\": {\"wt_account_id\":\"%s\"}}", appMetadata.WTAccountId)
	assert.Equal(t, expectedReqBody, jwtReqClient.reqBody, "request body should match")

}
