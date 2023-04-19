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

// AzureManager azure AD manager client instance.
type AzureManager struct {
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// AzureClientConfig azure AD manager client configurations.
type AzureClientConfig struct {
	ClientID         string
	ClientSecret     string
	GraphAPIEndpoint string
	TokenEndpoint    string
	GrantType        string
}

// AzureCredentials azure AD authentication information.
type AzureCredentials struct {
	clientConfig AzureClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewAzureManager creates a new instance of the AzureManager.
func NewAzureManager(config AzureClientConfig, appMetrics telemetry.AppMetrics) (*AzureManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}

	if config.ClientID == "" || config.ClientSecret == "" || config.GrantType == "" || config.GraphAPIEndpoint == "" || config.TokenEndpoint == "" {
		return nil, fmt.Errorf("azure idp configuration is not complete")
	}

	if config.GrantType != "client_credentials" {
		return nil, fmt.Errorf("azure idp configuration failed. Grant Type should be client_credentials")
	}

	credentials := &AzureCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &AzureManager{
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from azure.
func (ac *AzureCredentials) jwtStillValid() bool {
	return !ac.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(ac.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
func (ac *AzureCredentials) requestJWTToken() (*http.Response, error) {
	data := url.Values{}
	data.Set("client_id", ac.clientConfig.ClientID)
	data.Set("client_secret", ac.clientConfig.ClientSecret)
	data.Set("grant_type", ac.clientConfig.GrantType)
	data.Set("scope", "https://graph.microsoft.com/.default")

	payload := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, ac.clientConfig.TokenEndpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	log.Debug("requesting new jwt token for azure idp manager")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		if ac.appMetrics != nil {
			ac.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get azure token, statusCode %d", resp.StatusCode)
	}

	return resp, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (ac *AzureCredentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := io.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = ac.helper.Unmarshal(body, &jwtToken)
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
	err = ac.helper.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

// Authenticate retrieves access token to use the azure Management API.
func (ac *AzureCredentials) Authenticate() (JWTToken, error) {
	ac.mux.Lock()
	defer ac.mux.Unlock()

	if ac.appMetrics != nil {
		ac.appMetrics.IDPMetrics().CountAuthenticate()
	}

	// reuse the token without requesting a new one if it is not expired,
	// and if expiry time is sufficient time available to make a request.
	if ac.jwtStillValid() {
		return ac.jwtToken, nil
	}

	resp, err := ac.requestJWTToken()
	if err != nil {
		return ac.jwtToken, err
	}
	defer resp.Body.Close()

	jwtToken, err := ac.parseRequestJWTResponse(resp.Body)
	if err != nil {
		return ac.jwtToken, err
	}

	ac.jwtToken = jwtToken

	return ac.jwtToken, nil
}

func (am *AzureManager) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {
	return nil
}

func (am *AzureManager) GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error) {
	return &UserData{}, nil
}

func (am *AzureManager) GetAccount(accountId string) ([]*UserData, error) {
	return make([]*UserData, 0), nil
}
func (am *AzureManager) GetAllAccounts() (map[string][]*UserData, error) {
	return map[string][]*UserData{}, nil
}

func (am *AzureManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	return &UserData{}, nil
}

func (am *AzureManager) GetUserByEmail(email string) ([]*UserData, error) {
	return make([]*UserData, 0), nil
}
