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

type OktaManager struct {
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// OktaClientConfig okta manager client configurations.
type OktaClientConfig struct {
	ClientID      string
	ClientSecret  string
	Issuer        string
	TokenEndpoint string
	GrantType     string
}

// OktaCredentials okta authentication information.
type OktaCredentials struct {
	clientConfig OktaClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewOktaManager creates a new instance of the OktaManager.
func NewOktaManager(oidcConfig OIDCConfig, config OktaClientConfig,
	appMetrics telemetry.AppMetrics) (*OktaManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}
	config.Issuer = oidcConfig.Issuer
	config.TokenEndpoint = oidcConfig.TokenEndpoint
	config.GrantType = "client_credentials"

	if config.ClientID == "" {
		return nil, fmt.Errorf("okta IdP configuration is incomplete, clientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("okta IdP configuration is incomplete, ClientSecret is missing")
	}

	credentials := &OktaCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &OktaManager{
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from keycloak.
func (oc *OktaCredentials) jwtStillValid() bool {
	return !oc.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(oc.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
func (oc *OktaCredentials) requestJWTToken() (*http.Response, error) {
	data := url.Values{}
	data.Set("client_id", oc.clientConfig.ClientID)
	data.Set("client_secret", oc.clientConfig.ClientSecret)
	data.Set("grant_type", oc.clientConfig.GrantType)
	data.Set("scope", "api")

	payload := strings.NewReader(data.Encode())
	tokenURL := oc.clientConfig.Issuer + "/oauth2/default/v1/token"
	req, err := http.NewRequest(http.MethodPost, tokenURL, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	log.Debug("requesting new jwt token for okta idp manager")

	resp, err := oc.httpClient.Do(req)
	if err != nil {
		if oc.appMetrics != nil {
			oc.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get okta token, statusCode %d", resp.StatusCode)
	}

	return resp, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (oc *OktaCredentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := io.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = oc.helper.Unmarshal(body, &jwtToken)
	if err != nil {
		return jwtToken, err
	}

	if jwtToken.ExpiresIn == 0 && jwtToken.AccessToken == "" {
		return jwtToken, fmt.Errorf("error while reading response body, expires_in: %d and access_token: %s",
			jwtToken.ExpiresIn,
			jwtToken.AccessToken,
		)
	}

	data, err := jwt.DecodeSegment(strings.Split(jwtToken.AccessToken, ".")[1])
	if err != nil {
		return jwtToken, err
	}

	// Exp maps into exp from jwt token
	var IssuedAt struct{ Exp int64 }
	err = oc.helper.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

func (oc *OktaCredentials) Authenticate() (JWTToken, error) {
	oc.mux.Lock()
	defer oc.mux.Unlock()

	if oc.appMetrics != nil {
		oc.appMetrics.IDPMetrics().CountAuthenticate()
	}

	// reuse the token without requesting a new one if it is not expired,
	// and if expiry time is sufficient time available to make a request.
	if oc.jwtStillValid() {
		return oc.jwtToken, nil
	}

	resp, err := oc.requestJWTToken()
	if err != nil {
		return oc.jwtToken, err
	}
	defer resp.Body.Close()

	jwtToken, err := oc.parseRequestJWTResponse(resp.Body)
	if err != nil {
		return oc.jwtToken, err
	}

	oc.jwtToken = jwtToken

	return oc.jwtToken, nil
}

func (om *OktaManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (om *OktaManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (om *OktaManager) GetUserByEmail(email string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (om *OktaManager) GetAccount(accountID string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (om *OktaManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (om *OktaManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	//TODO implement me
	panic("implement me")
}
