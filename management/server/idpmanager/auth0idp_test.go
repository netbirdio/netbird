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
	code int
	body string
	err  error
}

func (c testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.code,
		Body:       ioutil.NopCloser(strings.NewReader(c.body)),
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
		inputBody               string
		expectedFuncExitErrDiff error
		expectedCode            int
		expectedToken           string
	}
	exp := 5
	token := newTestJWT(t, exp)

	jwtRequestTestCase1 := jwtRequestTest{
		name:      "Get Good JWT Response",
		inputCode: 200,
		inputBody: fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		//expectedFuncExitErrDiff: nil,
		expectedCode:  200,
		expectedToken: token,
	}
	jwtRequestTestCase2 := jwtRequestTest{
		name:                    "Get Bad Status Code",
		inputCode:               400,
		inputBody:               "{}",
		expectedFuncExitErrDiff: fmt.Errorf("unable to get token, statusCode 400"),
		expectedCode:            200,
		expectedToken:           "",
	}

	for _, testCase := range []jwtRequestTest{jwtRequestTestCase1, jwtRequestTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := testHTTPClient{
				body: testCase.inputBody,
				code: testCase.inputCode,
			}
			creds := Auth0ClientCredentials{}

			manager := NewAuth0Manager(creds)

			manager.httpClient = jwtReqClient

			res, err := manager.getJWTRequest()
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
		inputBody            string
		expectedToken        string
		expectedExpiresIn    int
		assertErrFunc        func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
		assertErrFuncMessage string
	}

	exp = 100
	token = newTestJWT(t, exp)

	jwtParseResponseTestCase1 := jwtParseResponseTest{
		name:                 "Parse Good JWT Body",
		inputBody:            fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		expectedToken:        token,
		expectedExpiresIn:    exp,
		assertErrFunc:        assert.NoError,
		assertErrFuncMessage: "no error was expected",
	}
	jwtParseResponseTestCase2 := jwtParseResponseTest{
		name:                 "Parse Bad json JWT Body",
		inputBody:            "",
		expectedToken:        "",
		expectedExpiresIn:    0,
		assertErrFunc:        assert.Error,
		assertErrFuncMessage: "json error was expected",
	}

	for _, testCase := range []jwtParseResponseTest{jwtParseResponseTestCase1, jwtParseResponseTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {

			rawBody := ioutil.NopCloser(strings.NewReader(testCase.inputBody))

			creds := Auth0ClientCredentials{}

			manager := NewAuth0Manager(creds)

			jwtToken, err := manager.parseGetJWTResponse(rawBody)
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

			creds := Auth0ClientCredentials{}

			manager := NewAuth0Manager(creds)
			manager.jwtToken.expiresInTime = testCase.inputTime

			assert.Equalf(t, testCase.expectedResult, manager.jwtStillValid(), testCase.message)
		})
	}
}
