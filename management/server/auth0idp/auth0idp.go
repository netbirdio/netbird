package auth0idp

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Auth0Manager struct {
	clientCredentials ClientCredentials
	jwtToken          JWTToken
	mux               sync.Mutex
}

type ClientCredentials struct {
	audiance     string
	authIssuer   string
	clientId     string
	clientSecret string
	grantType    string
}

type JWTToken struct {
	AccessToken   string `json:"access_token"`
	ExpiresIn     int    `json:"expires_in"`
	expiresInTime time.Time
	Scope         string `json:"scope"`
	TokenType     string `json:"token_type"`
}

// getJWTToken retrieves access token to use the Auth0 Management API
func (am *Auth0Manager) getJWTToken() error {
	am.mux.Lock()
	defer am.mux.Unlock()

	// If jwtToken has an expires time and we have enough time to do a request return immediately
	if !am.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(am.jwtToken.expiresInTime) {
		return nil
	}

	url := am.clientCredentials.authIssuer + "/oauth/token"

	payload := strings.NewReader(fmt.Sprintf(
		"{\"grant_type\":\"%s\",\"client_id\":\"%s\",\"client_secret\":\"%s\",\"audience\":\"%s\"}",
		am.clientCredentials.grantType,
		am.clientCredentials.clientId,
		am.clientCredentials.clientSecret,
		am.clientCredentials.audiance,
	))

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return err
	}

	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("unable to get token, statusCode %d", res.StatusCode)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(body, &am.jwtToken)
	if err != nil {
		return err
	}
	if am.jwtToken.ExpiresIn == 0 && am.jwtToken.AccessToken == "" {
		return fmt.Errorf("error while reading response body, expires_in: %d and access_token: %s", am.jwtToken.ExpiresIn, am.jwtToken.AccessToken)
	}

	data, err := jwt.DecodeSegment(strings.Split(am.jwtToken.AccessToken, ".")[1])
	if err != nil {
		return err
	}
	// Exp maps into exp from jwt token
	var IssuedAt struct{ Exp int64 }
	err = json.Unmarshal(data, &IssuedAt)
	if err != nil {
		return err
	}
	am.jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return nil
}

// UpdateUserMetadata updates user app metadata based on userId and metadata map
func (am *Auth0Manager) UpdateUserMetadata(userId string, metadata map[string]string) error {

	err := am.getJWTToken()
	if err != nil {
		return err
	}

	url := am.clientCredentials.authIssuer + "/api/v2/users/" + userId

	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	payloadString := fmt.Sprintf("{\"app_metadata\": %s}", string(data))

	payload := strings.NewReader(payloadString)
	fmt.Println(payloadString)

	req, _ := http.NewRequest("PATCH", url, payload)

	req.Header.Add("authorization", "Bearer "+am.jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("unable to update the metadata, statusCode %d", res.StatusCode)
	}

	return nil
}
