package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	log "github.com/sirupsen/logrus"
)

// KeycloakManager keycloak manager client instance.
type KeycloakManager struct {
	adminEndpoint string
	httpClient    ManagerHTTPClient
	credentials   ManagerCredentials
	helper        ManagerHelper
	appMetrics    telemetry.AppMetrics
}

// KeycloakClientConfig keycloak manager client configurations.
type KeycloakClientConfig struct {
	ClientID      string
	ClientSecret  string
	AdminEndpoint string
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

// keycloakUserCredential describe the authentication method for,
// newly created user profile.
type keycloakUserCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// keycloakUserAttributes holds additional user data fields.
type keycloakUserAttributes map[string][]string

// createUserRequest is a user create request.
type keycloakCreateUserRequest struct {
	Email         string                   `json:"email"`
	Username      string                   `json:"username"`
	Enabled       bool                     `json:"enabled"`
	EmailVerified bool                     `json:"emailVerified"`
	Credentials   []keycloakUserCredential `json:"credentials"`
	Attributes    keycloakUserAttributes   `json:"attributes"`
}

// keycloakProfile represents an keycloak user profile response.
type keycloakProfile struct {
	ID               string                 `json:"id"`
	CreatedTimestamp int64                  `json:"createdTimestamp"`
	Username         string                 `json:"username"`
	Email            string                 `json:"email"`
	Attributes       keycloakUserAttributes `json:"attributes"`
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

	if config.ClientID == "" || config.ClientSecret == "" || config.GrantType == "" || config.AdminEndpoint == "" || config.TokenEndpoint == "" {
		return nil, fmt.Errorf("keycloak idp configuration is not complete")
	}

	if config.GrantType != "client_credentials" {
		return nil, fmt.Errorf("keycloak idp configuration failed. Grant Type should be client_credentials")
	}

	credentials := &KeycloakCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &KeycloakManager{
		adminEndpoint: config.AdminEndpoint,
		httpClient:    httpClient,
		credentials:   credentials,
		helper:        helper,
		appMetrics:    appMetrics,
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

	if resp.StatusCode != http.StatusOK {
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
	err = kc.helper.Unmarshal(data, &IssuedAt)
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

// CreateUser creates a new user in keycloak Idp and sends an invite.
func (km *KeycloakManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	jwtToken, err := km.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	invite := true
	appMetadata := AppMetadata{
		WTAccountID:     accountID,
		WTPendingInvite: &invite,
	}

	payloadString, err := buildKeycloakCreateUserRequestPayload(email, name, appMetadata)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/users", km.adminEndpoint)
	payload := strings.NewReader(payloadString)

	req, err := http.NewRequest(http.MethodPost, reqURL, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountCreateUser()
	}

	resp, err := km.httpClient.Do(req)
	if err != nil {
		if km.appMetrics != nil {
			km.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		if km.appMetrics != nil {
			km.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return nil, fmt.Errorf("unable to create user, statusCode %d", resp.StatusCode)
	}

	locationHeader := resp.Header.Get("location")
	userID, err := extractUserIDFromLocationHeader(locationHeader)
	if err != nil {
		return nil, err
	}

	return km.GetUserDataByID(userID, appMetadata)
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (km *KeycloakManager) GetUserByEmail(email string) ([]*UserData, error) {
	q := url.Values{}
	q.Add("email", email)
	q.Add("exact", "true")

	body, err := km.get("users", q)
	if err != nil {
		return nil, err
	}

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	profiles := make([]keycloakProfile, 0)
	err = km.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles {
		users = append(users, profile.userData())
	}

	return users, nil
}

// GetUserDataByID requests user data from keycloak via ID.
func (km *KeycloakManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	body, err := km.get("users/"+userID, nil)
	if err != nil {
		return nil, err
	}

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	var profile keycloakProfile
	err = km.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	return profile.userData(), nil
}

// GetAccount returns all the users for a given profile.
func (km *KeycloakManager) GetAccount(accountID string) ([]*UserData, error) {
	q := url.Values{}
	q.Add("q", "wt_account_id:"+accountID)

	body, err := km.get("users", q)
	if err != nil {
		return nil, err
	}

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountGetAccount()
	}

	profiles := make([]keycloakProfile, 0)
	err = km.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles {
		users = append(users, profile.userData())
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (km *KeycloakManager) GetAllAccounts() (map[string][]*UserData, error) {
	totalUsers, err := km.totalUsersCount()
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Add("max", fmt.Sprint(*totalUsers))

	body, err := km.get("users", q)
	if err != nil {
		return nil, err
	}

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	profiles := make([]keycloakProfile, 0)
	err = km.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	for _, profile := range profiles {
		userData := profile.userData()

		accountID := userData.AppMetadata.WTAccountID
		if accountID != "" {
			if _, ok := indexedUsers[accountID]; !ok {
				indexedUsers[accountID] = make([]*UserData, 0)
			}
			indexedUsers[accountID] = append(indexedUsers[accountID], userData)
		}
	}

	return indexedUsers, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (km *KeycloakManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	jwtToken, err := km.credentials.Authenticate()
	if err != nil {
		return err
	}

	attrs := keycloakUserAttributes{}
	attrs.Set("wt_account_id", appMetadata.WTAccountID)
	if appMetadata.WTPendingInvite != nil {
		attrs.Set("wt_pending_invite", strconv.FormatBool(*appMetadata.WTPendingInvite))
	} else {
		attrs.Set("wt_pending_invite", "false")
	}

	reqURL := fmt.Sprintf("%s/users/%s", km.adminEndpoint, userID)
	data, err := km.helper.Marshal(map[string]any{
		"attributes": attrs,
	})
	if err != nil {
		return err
	}
	payload := strings.NewReader(string(data))

	req, err := http.NewRequest(http.MethodPut, reqURL, payload)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	log.Debugf("updating IdP metadata for user %s", userID)

	resp, err := km.httpClient.Do(req)
	if err != nil {
		if km.appMetrics != nil {
			km.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}
	defer resp.Body.Close()

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unable to update the appMetadata, statusCode %d", resp.StatusCode)
	}

	return nil
}

func buildKeycloakCreateUserRequestPayload(email string, name string, appMetadata AppMetadata) (string, error) {
	attrs := keycloakUserAttributes{}
	attrs.Set("wt_account_id", appMetadata.WTAccountID)
	attrs.Set("wt_pending_invite", strconv.FormatBool(*appMetadata.WTPendingInvite))

	req := &keycloakCreateUserRequest{
		Email:         email,
		Username:      name,
		Enabled:       true,
		EmailVerified: true,
		Credentials: []keycloakUserCredential{
			{
				Type:      "password",
				Value:     GeneratePassword(8, 1, 1, 1),
				Temporary: false,
			},
		},
		Attributes: attrs,
	}

	str, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

// get perform Get requests.
func (km *KeycloakManager) get(resource string, q url.Values) ([]byte, error) {
	jwtToken, err := km.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/%s?%s", km.adminEndpoint, resource, q.Encode())
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	resp, err := km.httpClient.Do(req)
	if err != nil {
		if km.appMetrics != nil {
			km.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if km.appMetrics != nil {
			km.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return nil, fmt.Errorf("unable to get %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// totalUsersCount returns the total count of all user created.
// Used when fetching all registered accounts with pagination.
func (km *KeycloakManager) totalUsersCount() (*int, error) {
	body, err := km.get("users/count", nil)
	if err != nil {
		return nil, err
	}

	count, err := strconv.Atoi(string(body))
	if err != nil {
		return nil, err
	}

	return &count, nil
}

// extractUserIDFromLocationHeader extracts the user ID from the location,
// header once the user is created successfully
func extractUserIDFromLocationHeader(locationHeader string) (string, error) {
	userURL, err := url.Parse(locationHeader)
	if err != nil {
		return "", err
	}

	return path.Base(userURL.Path), nil
}

// userData construct user data from keycloak profile.
func (kp keycloakProfile) userData() *UserData {
	accountID := kp.Attributes.Get("wp_account_id")
	pendingInvite, err := strconv.ParseBool(kp.Attributes.Get("wt_pending_invite"))
	if err != nil {
		pendingInvite = false
	}

	return &UserData{
		Email: kp.Email,
		Name:  kp.Username,
		ID:    kp.ID,
		AppMetadata: AppMetadata{
			WTAccountID:     accountID,
			WTPendingInvite: &pendingInvite,
		},
	}
}

// Set sets the key to value. It replaces any existing
// values.
func (ka keycloakUserAttributes) Set(key, value string) {
	ka[key] = []string{value}
}

// Get returns the first value associated with the given key.
// If there are no values associated with the key, Get returns
// the empty string.
func (ka keycloakUserAttributes) Get(key string) string {
	if ka == nil {
		return ""
	}

	values := ka[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
