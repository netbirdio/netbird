package idpmanager

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
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
	t.Log(tokenString)
	return tokenString
}

func TestAuth0_GetJWTToken(t *testing.T) {

	exp := 5
	token := newTestJWT(t, exp)

	type jwtRequest struct {
		name      string
		inputCode int
		inputBody string

		expectedCode  int
		expectedToken string
	}

	t.Run("Get_JWT_Request", func(t *testing.T) {

		jwtReqClient := testHTTPClient{
			body: fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		}
		creds := Auth0ClientCredentials{}

		manager := NewAuth0Manager(creds)

		manager.httpClient = jwtReqClient

		res, err := manager.getJWTRequest()
		if err != nil {
			t.Error(err)
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		jwtToken := JWTToken{}
		err = json.Unmarshal(body, &jwtToken)
		if err != nil {
			t.Fatal(err)
		}
		if jwtToken.AccessToken == "" {
			t.Fatalf("access token returned empty")
		}
	})

	t.Run("Parse_JWT_Response", func(t *testing.T) {

		jwtReqClient := testHTTPClient{
			body: fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		}
		creds := Auth0ClientCredentials{}

		manager := NewAuth0Manager(creds)

		manager.httpClient = jwtReqClient
		res, err := manager.getJWTRequest()
		if err != nil {
			t.Error(err)
		}
		jwtToken, err := manager.parseGetJWTResponse(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if jwtToken.ExpiresIn == 0 {
			t.Error("jwt token was incorrectly parsed. Expires In is 0")
		}
	})

}
