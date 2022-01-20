package idpmanager

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Auth0Manager struct {
	clientCredentials Auth0ClientCredentials
	jwtToken          JWTToken
	mux               sync.Mutex
	httpClient        Auth0HTTPClient
}

type Auth0ClientCredentials struct {
	Audience     string `json:"audiance"`
	AuthIssuer   string `json:"auth_issuer"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}

type Auth0HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewAuth0Manager creates a new instance of the Auth0Manager
func NewAuth0Manager(credentials Auth0ClientCredentials) *Auth0Manager {
	return &Auth0Manager{
		clientCredentials: credentials,
		httpClient:        http.DefaultClient,
	}
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from Auth0
func (am *Auth0Manager) jwtStillValid() bool {
	return !am.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(am.jwtToken.expiresInTime)
}

// getJWTRequest performs request to get jwt token
func (am *Auth0Manager) getJWTRequest() (*http.Response, error) {
	var res *http.Response
	url := am.clientCredentials.AuthIssuer + "/oauth/token"

	p, err := json.Marshal(am.clientCredentials)
	if err != nil {
		return res, err
	}
	payload := strings.NewReader(string(p))

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return res, err
	}

	req.Header.Add("content-type", "application/json")

	res, err = am.httpClient.Do(req)
	if err != nil {
		return res, err
	}

	if res.StatusCode != 200 {
		return res, fmt.Errorf("unable to get token, statusCode %d", res.StatusCode)
	}
	return res, nil
}

// parseGetJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (am *Auth0Manager) parseGetJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := ioutil.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = json.Unmarshal(body, &jwtToken)
	if err != nil {
		return jwtToken, err
	}
	if jwtToken.ExpiresIn == 0 && jwtToken.AccessToken == "" {
		return jwtToken, fmt.Errorf("error while reading response body, expires_in: %d and access_token: %s", jwtToken.ExpiresIn, jwtToken.AccessToken)
	}
	data, err := jwt.DecodeSegment(strings.Split(jwtToken.AccessToken, ".")[1])
	if err != nil {
		return jwtToken, err
	}
	// Exp maps into exp from jwt token
	var IssuedAt struct{ Exp int64 }
	err = json.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

// getJWTToken retrieves access token to use the Auth0 Management API
func (am *Auth0Manager) getJWTToken() error {
	am.mux.Lock()
	defer am.mux.Unlock()

	// If jwtToken has an expires time and we have enough time to do a request return immediately
	if am.jwtStillValid() {
		return nil
	}

	res, err := am.getJWTRequest()
	if err != nil {
		return err
	}
	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Errorf("error while closing get jwt token response body: %v", err)
		}
	}()

	jwtToken, err := am.parseGetJWTResponse(res.Body)
	if err != nil {
		return err
	}

	am.jwtToken = jwtToken

	return nil
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map
func (am *Auth0Manager) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {

	err := am.getJWTToken()
	if err != nil {
		return err
	}

	url := am.clientCredentials.AuthIssuer + "/api/v2/users/" + userId

	data, err := json.Marshal(appMetadata)
	if err != nil {
		return err
	}

	payloadString := fmt.Sprintf("{\"app_metadata\": %s}", string(data))

	payload := strings.NewReader(payloadString)

	req, err := http.NewRequest("PATCH", url, payload)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+am.jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	res, err := am.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Errorf("error while closing update user app metadata response body: %v", err)
		}
	}()

	if res.StatusCode != 200 {
		return fmt.Errorf("unable to update the appMetadata, statusCode %d", res.StatusCode)
	}

	return nil
}
