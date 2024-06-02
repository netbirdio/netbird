package idp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"goauthentik.io/api/v3"

	"github.com/netbirdio/netbird/management/server/telemetry"
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
	Issuer        string
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
func NewAuthentikManager(config AuthentikClientConfig,
	appMetrics telemetry.AppMetrics) (*AuthentikManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}

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

	if config.Issuer == "" {
		return nil, fmt.Errorf("authentik IdP configuration is incomplete, Issuer is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("authentik IdP configuration is incomplete, GrantType is missing")
	}

	// authentik client configuration
	issuerURL, err := url.Parse(config.Issuer)
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
func (am *AuthentikManager) UpdateUserAppMetadata(_ string, _ AppMetadata) error {
	return nil
}

// GetUserDataByID requests user data from authentik via ID.
func (am *AuthentikManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	ctx, err := am.authenticationContext()
	if err != nil {
		return nil, err
	}

	userPk, err := strconv.ParseInt(userID, 10, 32)
	if err != nil {
		return nil, err
	}

	user, resp, err := am.apiClient.CoreApi.CoreUsersRetrieve(ctx, int32(userPk)).Execute()
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	if resp.StatusCode != http.StatusOK {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", userID, resp.StatusCode)
	}

	userData := parseAuthentikUser(*user)
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetAccount returns all the users for a given profile.
func (am *AuthentikManager) GetAccount(accountID string) ([]*UserData, error) {
	users, err := am.getAllUsers()
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetAccount()
	}

	for index, user := range users {
		user.AppMetadata.WTAccountID = accountID
		users[index] = user
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (am *AuthentikManager) GetAllAccounts() (map[string][]*UserData, error) {
	users, err := am.getAllUsers()
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], users...)

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	return indexedUsers, nil
}

// getAllUsers returns all users in a Authentik account.
func (am *AuthentikManager) getAllUsers() ([]*UserData, error) {
	users := make([]*UserData, 0)

	page := int32(1)
	for {
		ctx, err := am.authenticationContext()
		if err != nil {
			return nil, err
		}

		userList, resp, err := am.apiClient.CoreApi.CoreUsersList(ctx).Page(page).Execute()
		if err != nil {
			return nil, err
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if am.appMetrics != nil {
				am.appMetrics.IDPMetrics().CountRequestStatusError()
			}
			return nil, fmt.Errorf("unable to get all accounts, statusCode %d", resp.StatusCode)
		}

		for _, user := range userList.Results {
			users = append(users, parseAuthentikUser(user))
		}

		page = int32(userList.GetPagination().Next)
		if userList.GetPagination().Next == 0 {
			break
		}

	}

	return users, nil
}

// CreateUser creates a new user in authentik Idp and sends an invitation.
func (am *AuthentikManager) CreateUser(_, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
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
	defer resp.Body.Close()

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
		users = append(users, parseAuthentikUser(user))
	}

	return users, nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (am *AuthentikManager) InviteUserByID(_ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from Authentik
func (am *AuthentikManager) DeleteUser(userID string) error {
	ctx, err := am.authenticationContext()
	if err != nil {
		return err
	}

	userPk, err := strconv.ParseInt(userID, 10, 32)
	if err != nil {
		return err
	}

	resp, err := am.apiClient.CoreApi.CoreUsersDestroy(ctx, int32(userPk)).Execute()
	if err != nil {
		return err
	}
	defer resp.Body.Close() // nolint

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountDeleteUser()
	}

	if resp.StatusCode != http.StatusNoContent {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to delete user %s, statusCode %d", userID, resp.StatusCode)
	}

	return nil
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

func parseAuthentikUser(user api.User) *UserData {
	return &UserData{
		Email: *user.Email,
		Name:  user.Name,
		ID:    strconv.FormatInt(int64(user.Pk), 10),
	}
}
