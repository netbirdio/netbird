package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

// Auth0Manager auth0 manager client instance
type Auth0Manager struct {
	authIssuer  string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
}

// Auth0ClientConfig auth0 manager client configurations
type Auth0ClientConfig struct {
	Audience     string
	AuthIssuer   string
	ClientID     string
	ClientSecret string
	GrantType    string
}

// auth0JWTRequest payload struct to request a JWT Token
type auth0JWTRequest struct {
	Audience     string `json:"audience"`
	AuthIssuer   string `json:"auth_issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}

// Auth0Credentials auth0 authentication information
type Auth0Credentials struct {
	clientConfig Auth0ClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
}

// NewAuth0Manager creates a new instance of the Auth0Manager
func NewAuth0Manager(config Auth0ClientConfig) (*Auth0Manager, error) {

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}

	if config.ClientID == "" || config.ClientSecret == "" || config.GrantType == "" || config.Audience == "" || config.AuthIssuer == "" {
		return nil, fmt.Errorf("auth0 idp configuration is not complete")
	}

	if config.GrantType != "client_credentials" {
		return nil, fmt.Errorf("auth0 idp configuration failed. Grant Type should be client_credentials")
	}

	if !strings.HasPrefix(strings.ToLower(config.AuthIssuer), "https://") {
		return nil, fmt.Errorf("auth0 idp configuration failed. AuthIssuer should contain https://")
	}

	credentials := &Auth0Credentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
	}
	return &Auth0Manager{
		authIssuer:  config.AuthIssuer,
		credentials: credentials,
		httpClient:  httpClient,
		helper:      helper,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from Auth0
func (c *Auth0Credentials) jwtStillValid() bool {
	return !c.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(c.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token
func (c *Auth0Credentials) requestJWTToken() (*http.Response, error) {
	var res *http.Response
	url := c.clientConfig.AuthIssuer + "/oauth/token"

	p, err := c.helper.Marshal(auth0JWTRequest(c.clientConfig))
	if err != nil {
		return res, err
	}
	payload := strings.NewReader(string(p))

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return res, err
	}

	req.Header.Add("content-type", "application/json")

	log.Debug("requesting new jwt token for idp manager")

	res, err = c.httpClient.Do(req)
	if err != nil {
		return res, err
	}

	if res.StatusCode != 200 {
		return res, fmt.Errorf("unable to get token, statusCode %d", res.StatusCode)
	}
	return res, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (c *Auth0Credentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := ioutil.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = c.helper.Unmarshal(body, &jwtToken)
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

// Authenticate retrieves access token to use the Auth0 Management API
func (c *Auth0Credentials) Authenticate() (JWTToken, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	// If jwtToken has an expires time and we have enough time to do a request return immediately
	if c.jwtStillValid() {
		return c.jwtToken, nil
	}

	res, err := c.requestJWTToken()
	if err != nil {
		return c.jwtToken, err
	}
	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Errorf("error while closing get jwt token response body: %v", err)
		}
	}()

	jwtToken, err := c.parseRequestJWTResponse(res.Body)
	if err != nil {
		return c.jwtToken, err
	}

	c.jwtToken = jwtToken

	return c.jwtToken, nil
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map
func (am *Auth0Manager) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {

	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return err
	}

	url := am.authIssuer + "/api/v2/users/" + userId

	data, err := am.helper.Marshal(appMetadata)
	if err != nil {
		return err
	}

	payloadString := fmt.Sprintf("{\"app_metadata\": %s}", string(data))

	payload := strings.NewReader(payloadString)

	req, err := http.NewRequest("PATCH", url, payload)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	log.Debugf("updating metadata for user %s", userId)

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
