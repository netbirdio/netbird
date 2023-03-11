package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	log "github.com/sirupsen/logrus"
)

// KeycloakManager keycloak manager client instance.
type KeycloakManager struct {
	authIssuer  string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// KeycloakClientConfig keycloak manager client configurations.
type KeycloakClientConfig struct {
	Audience      string
	AuthIssuer    string
	ClientID      string
	ClientSecret  string
	TokenEndpoint string
	GrantType     string
}

// KeycloakCredentials keycloak authentication information.
type KeycloakCredentials struct {
	clientConfig KeycloakClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewKeycloakManager creates a new instance of the KeycloakManager.
func NewKeycloakManager(config KeycloakClientConfig, appMetrics telemetry.AppMetrics) (*KeycloakManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}

	if config.ClientID == "" || config.ClientSecret == "" || config.GrantType == "" || config.Audience == "" || config.AuthIssuer == "" || config.TokenEndpoint == "" {
		return nil, fmt.Errorf("keycloak idp configuration is not complete")
	}

	if config.GrantType != "client_credentials" {
		return nil, fmt.Errorf("keycloak idp configuration failed. Grant Type should be client_credentials")
	}

	if !strings.HasPrefix(strings.ToLower(config.AuthIssuer), "https://") {
		return nil, fmt.Errorf("keycloak idp configuration failed. AuthIssuer should contain https://")
	}

	credentials := &KeycloakCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &KeycloakManager{
		authIssuer:  config.AuthIssuer,
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from keycloak.
func (kc *KeycloakCredentials) jwtStillValid() bool {
	return !kc.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(kc.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
func (kc *KeycloakCredentials) requestJWTToken() (*http.Response, error) {
	data := url.Values{}
	data.Set("client_id", kc.clientConfig.ClientID)
	data.Set("client_secret", kc.clientConfig.ClientSecret)
	data.Set("grant_type", kc.clientConfig.GrantType)

	payload := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, kc.clientConfig.TokenEndpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	log.Debug("requesting new jwt token for keycloak idp manager")

	resp, err := kc.httpClient.Do(req)
	if err != nil {
		if kc.appMetrics != nil {
			kc.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unable to get keycloak token, statusCode %d", resp.StatusCode)
	}

	return resp, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (kc *KeycloakCredentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := io.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = kc.helper.Unmarshal(body, &jwtToken)
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

// Authenticate retrieves access token to use the keycloak Management API.
func (kc *KeycloakCredentials) Authenticate() (JWTToken, error) {
	kc.mux.Lock()
	defer kc.mux.Unlock()

	if kc.appMetrics != nil {
		kc.appMetrics.IDPMetrics().CountAuthenticate()
	}

	// reuse the token without requesting a new one if it is not expired,
	// and if expiry time is sufficient time available to make a request.
	if kc.jwtStillValid() {
		return kc.jwtToken, nil
	}

	resp, err := kc.requestJWTToken()
	if err != nil {
		return kc.jwtToken, err
	}
	defer resp.Body.Close()

	jwtToken, err := kc.parseRequestJWTResponse(resp.Body)
	if err != nil {
		return kc.jwtToken, err
	}

	kc.jwtToken = jwtToken

	return kc.jwtToken, nil
}

// CreateUser creates a new user in Auth0 Idp and sends an invite.
func (km *KeycloakManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (km *KeycloakManager) GetUserByEmail(email string) ([]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetUserDataByID requests user data from auth0 via ID.
func (km *KeycloakManager) GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map.
func (km *KeycloakManager) GetAccount(accountId string) ([]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (km *KeycloakManager) GetAllAccounts() (map[string][]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map.
func (km *KeycloakManager) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {
	panic("not implemented") // TODO: Implement
}
