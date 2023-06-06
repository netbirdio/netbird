package idp

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GoogleManager google manager client instance.
type GoogleManager struct {
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// GoogleClientConfig google manager client configurations.
type GoogleClientConfig struct {
	ClientID      string
	ClientSecret  string
	TokenEndpoint string
	GrantType     string
}

// GoogleCredentials google authentication information.
type GoogleCredentials struct {
	clientConfig GoogleClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from azure.
func (gc *GoogleCredentials) jwtStillValid() bool {
	return !gc.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(gc.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
func (gc *GoogleCredentials) requestJWTToken() (*http.Response, error) {
	data := url.Values{}
	data.Set("client_id", gc.clientConfig.ClientID)
	data.Set("client_secret", gc.clientConfig.ClientSecret)
	data.Set("grant_type", gc.clientConfig.GrantType)

	payload := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, gc.clientConfig.TokenEndpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	log.Debug("requesting new jwt token for google idp manager")

	resp, err := gc.httpClient.Do(req)
	if err != nil {
		if gc.appMetrics != nil {
			gc.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get google token, statusCode %d", resp.StatusCode)
	}

	return resp, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (gc *GoogleCredentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := io.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = gc.helper.Unmarshal(body, &jwtToken)
	if err != nil {
		return jwtToken, err
	}

	if jwtToken.ExpiresIn == 0 && jwtToken.AccessToken == "" {
		return jwtToken, fmt.Errorf("error while reading response body, expires_in: %d and gccess_token: %s", jwtToken.ExpiresIn, jwtToken.AccessToken)
	}

	data, err := jwt.DecodeSegment(strings.Split(jwtToken.AccessToken, ".")[1])
	if err != nil {
		return jwtToken, err
	}

	// Exp maps into exp from jwt token
	var IssuedAt struct{ Exp int64 }
	err = gc.helper.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

func (gc *GoogleCredentials) Authenticate() (JWTToken, error) {
	gc.mux.Lock()
	defer gc.mux.Unlock()

	if gc.appMetrics != nil {
		gc.appMetrics.IDPMetrics().CountAuthenticate()
	}

	// reuse the token without requesting a new one if it is not expired,
	// and if expiry time is sufficient time available to make a request.
	if gc.jwtStillValid() {
		return gc.jwtToken, nil
	}

	resp, err := gc.requestJWTToken()
	if err != nil {
		return gc.jwtToken, err
	}
	defer resp.Body.Close()

	jwtToken, err := gc.parseRequestJWTResponse(resp.Body)
	if err != nil {
		return gc.jwtToken, err
	}

	gc.jwtToken = jwtToken

	return gc.jwtToken, nil
}

// NewGoogleManager creates a new instance of the GoogleManager.
func NewGoogleManager(config GoogleClientConfig, appMetrics telemetry.AppMetrics) (*GoogleManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.ClientID == "" {
		return nil, fmt.Errorf("google IdP configuration is incomplete, clientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("google IdP configuration is incomplete, ClientSecret is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("google IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("google IdP configuration is incomplete, GrantType is missing")
	}

	credentials := &GoogleCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &GoogleManager{
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

func (gm *GoogleManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetAccount(gccountID string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) CreateUser(email string, name string, gccountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetUserByEmail(email string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}
