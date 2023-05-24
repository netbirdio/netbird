package idp

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	log "github.com/sirupsen/logrus"
	"goauthentik.io/api/v3"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthentikManager authentik manager client instance.
type AuthentikManager struct {
	apiClient   *api.APIClient
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// AuthentikClientConfig authentik manager client configurations.
type AuthentikClientConfig struct {
	ClientID      string
	Username      string
	Password      string
	TokenEndpoint string
	GrantType     string
}

// AuthentikCredentials authentik authentication information.
type AuthentikCredentials struct {
	clientConfig AuthentikClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewAuthentikManager creates a new instance of the AuthentikManager.
func NewAuthentikManager(oidcConfig OIDCConfig, config AuthentikClientConfig,
	appMetrics telemetry.AppMetrics) (*AuthentikManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}
	config.TokenEndpoint = oidcConfig.TokenEndpoint
	config.GrantType = "client_credentials"

	if config.ClientID == "" {
		return nil, fmt.Errorf("authentik IdP configuration is incomplete, clientID is missing")
	}

	if config.Username == "" {
		return nil, fmt.Errorf("authentik IdP configuration is incomplete, Username is missing")
	}

	if config.Password == "" {
		return nil, fmt.Errorf("authentik IdP configuration is incomplete, Password is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("authentik IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("authentik IdP configuration is incomplete, GrantType is missing")
	}

	// authentik client configuration
	issuerURL, err := url.Parse(oidcConfig.Issuer)
	if err != nil {
		return nil, err
	}
	authentikConfig := api.NewConfiguration()
	authentikConfig.HTTPClient = httpClient
	authentikConfig.Host = issuerURL.Host
	authentikConfig.Scheme = issuerURL.Scheme

	credentials := &AuthentikCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &AuthentikManager{
		apiClient:   api.NewAPIClient(authentikConfig),
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from authentik.
func (ac *AuthentikCredentials) jwtStillValid() bool {
	return !ac.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(ac.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
func (ac *AuthentikCredentials) requestJWTToken() (*http.Response, error) {
	data := url.Values{}
	data.Set("client_id", ac.clientConfig.ClientID)
	data.Set("username", ac.clientConfig.Username)
	data.Set("password", ac.clientConfig.Password)
	data.Set("grant_type", ac.clientConfig.GrantType)
	data.Set("scope", "goauthentik.io/api")

	payload := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, ac.clientConfig.TokenEndpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	log.Debug("requesting new jwt token for authentik idp manager")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		if ac.appMetrics != nil {
			ac.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get authentik token, statusCode %d", resp.StatusCode)
	}

	return resp, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (ac *AuthentikCredentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
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

// Authenticate retrieves access token to use the authentik management API.
func (ac *AuthentikCredentials) Authenticate() (JWTToken, error) {
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

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (am *AuthentikManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	//TODO implement me
	panic("implement me")
}

// GetUserDataByID requests user data from authentik via ID.
func (am *AuthentikManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	//am.apiClient.CoreApi.CoreUsersList().Uuid()
	return nil, nil
}

// GetAccount returns all the users for a given profile.
func (am *AuthentikManager) GetAccount(accountID string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (am *AuthentikManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// CreateUser creates a new user in authentik Idp and sends an invite.
func (am *AuthentikManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (am *AuthentikManager) GetUserByEmail(email string) ([]*UserData, error) {
	ctx, err := am.authenticationContext()
	if err != nil {
		return nil, err
	}

	userList, resp, err := am.apiClient.CoreApi.CoreUsersList(ctx).Email(email).Execute()
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	if resp.StatusCode != http.StatusOK {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", email, resp.StatusCode)
	}

	users := make([]*UserData, 0)
	for _, user := range userList.Results {
		userData, err := parseAuthentikUser(user)
		if err != nil {
			return nil, err
		}
		users = append(users, userData)
	}

	return users, nil
}

func (am *AuthentikManager) authenticationContext() (context.Context, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	value := map[string]api.APIKey{
		"authentik": {
			Key:    jwtToken.AccessToken,
			Prefix: jwtToken.TokenType,
		},
	}
	return context.WithValue(context.Background(), api.ContextAPIKeys, value), nil
}

func parseAuthentikUser(user api.User) (*UserData, error) {
	var attributes struct {
		AccountID     string `json:"wt_account_id"`
		PendingInvite bool   `json:"wt_pending_invite"`
	}

	helper := JsonParser{}
	buf, err := helper.Marshal(user.Attributes)
	if err != nil {
		return nil, err
	}

	err = helper.Unmarshal(buf, &attributes)
	if err != nil {
		return nil, err
	}

	return &UserData{
		Email: *user.Email,
		Name:  user.Name,
		ID:    user.Uid,
		AppMetadata: AppMetadata{
			WTAccountID:     attributes.AccountID,
			WTPendingInvite: &attributes.PendingInvite,
		},
	}, nil
}
