package idp

import (
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

// ZitadelManager zitadel manager client instance.
type ZitadelManager struct {
	ManagementEndpoint string
	httpClient         ManagerHTTPClient
	credentials        ManagerCredentials
	helper             ManagerHelper
	appMetrics         telemetry.AppMetrics
}

// ZitadelClientConfig zitadel manager client configurations.
type ZitadelClientConfig struct {
	ClientID           string
	ClientSecret       string
	GrantType          string
	TokenEndpoint      string
	ManagementEndpoint string
}

// ZitadelCredentials zitadel authentication information.
type ZitadelCredentials struct {
	clientConfig ZitadelClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewZitadelManager creates a new instance of the ZitadelManager.
func NewZitadelManager(config ZitadelClientConfig, appMetrics telemetry.AppMetrics) (*ZitadelManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}

	if config.ClientID == "" || config.ClientSecret == "" || config.GrantType == "" || config.ManagementEndpoint == "" || config.TokenEndpoint == "" {
		return nil, fmt.Errorf("zitadel idp configuration is not complete")
	}

	if config.GrantType != "client_credentials" {
		return nil, fmt.Errorf("zitadel idp configuration failed. Grant Type should be client_credentials")
	}

	credentials := &ZitadelCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &ZitadelManager{
		ManagementEndpoint: config.ManagementEndpoint,
		httpClient:         httpClient,
		credentials:        credentials,
		helper:             helper,
		appMetrics:         appMetrics,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from zitadel.
func (zc *ZitadelCredentials) jwtStillValid() bool {
	return !zc.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(zc.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
func (zc *ZitadelCredentials) requestJWTToken() (*http.Response, error) {
	data := url.Values{}
	data.Set("client_id", zc.clientConfig.ClientID)
	data.Set("client_secret", zc.clientConfig.ClientSecret)
	data.Set("grant_type", zc.clientConfig.GrantType)
	data.Set("scope", "urn:zitadel:iam:org:project:id:zitadel:aud")

	payload := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, zc.clientConfig.TokenEndpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	log.Debug("requesting new jwt token for zitadel idp manager")

	resp, err := zc.httpClient.Do(req)
	if err != nil {
		if zc.appMetrics != nil {
			zc.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get zitadel token, statusCode %d", resp.StatusCode)
	}

	return resp, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds.
func (zc *ZitadelCredentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := io.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = zc.helper.Unmarshal(body, &jwtToken)
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
	err = zc.helper.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

// Authenticate retrieves access token to use the Zitadel Management API.
func (zc *ZitadelCredentials) Authenticate() (JWTToken, error) {
	zc.mux.Lock()
	defer zc.mux.Unlock()

	if zc.appMetrics != nil {
		zc.appMetrics.IDPMetrics().CountAuthenticate()
	}

	// reuse the token without requesting a new one if it is not expired,
	// and if expiry time is sufficient time available to make a request.
	if zc.jwtStillValid() {
		return zc.jwtToken, nil
	}

	resp, err := zc.requestJWTToken()
	if err != nil {
		return zc.jwtToken, err
	}
	defer resp.Body.Close()

	jwtToken, err := zc.parseRequestJWTResponse(resp.Body)
	if err != nil {
		return zc.jwtToken, err
	}

	zc.jwtToken = jwtToken

	return zc.jwtToken, nil
}

// CreateUser creates a new user in zitadel Idp and sends an invite.
func (zm *ZitadelManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	return nil, nil
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (zm *ZitadelManager) GetUserByEmail(email string) ([]*UserData, error) {
	return nil, nil
}

// GetUserDataByID requests user data from keycloak via ID.
func (zm *ZitadelManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	return nil, nil
}

// GetAccount returns all the users for a given profile.
func (zm *ZitadelManager) GetAccount(accountID string) ([]*UserData, error) {
	return nil, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (zm *ZitadelManager) GetAllAccounts() (map[string][]*UserData, error) {
	return nil, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (zm *ZitadelManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	return nil
}
