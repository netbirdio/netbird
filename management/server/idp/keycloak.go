package idp

import (
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

	"github.com/netbirdio/netbird/management/server/telemetry"
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

// keycloakUserAttributes holds additional user data fields.
type keycloakUserAttributes map[string][]string

// keycloakProfile represents a keycloak user profile response.
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

	if config.ClientID == "" {
		return nil, fmt.Errorf("keycloak IdP configuration is incomplete, clientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("keycloak IdP configuration is incomplete, ClientSecret is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("keycloak IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.AdminEndpoint == "" {
		return nil, fmt.Errorf("keycloak IdP configuration is incomplete, AdminEndpoint is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("keycloak IdP configuration is incomplete, GrantType is missing")
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
func (km *KeycloakManager) CreateUser(_, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
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
func (km *KeycloakManager) GetUserDataByID(userID string, _ AppMetadata) (*UserData, error) {
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

// GetAccount returns all the users for a given account profile.
func (km *KeycloakManager) GetAccount(accountID string) ([]*UserData, error) {
	profiles, err := km.fetchAllUserProfiles()
	if err != nil {
		return nil, err
	}

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountGetAccount()
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles {
		userData := profile.userData()
		userData.AppMetadata.WTAccountID = accountID

		users = append(users, userData)
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (km *KeycloakManager) GetAllAccounts() (map[string][]*UserData, error) {
	profiles, err := km.fetchAllUserProfiles()
	if err != nil {
		return nil, err
	}

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	indexedUsers := make(map[string][]*UserData)
	for _, profile := range profiles {
		userData := profile.userData()
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], userData)
	}

	return indexedUsers, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (km *KeycloakManager) UpdateUserAppMetadata(_ string, _ AppMetadata) error {
	return nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (km *KeycloakManager) InviteUserByID(_ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from Keycloak by user ID.
func (km *KeycloakManager) DeleteUser(userID string) error {
	jwtToken, err := km.credentials.Authenticate()
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/users/%s", km.adminEndpoint, url.QueryEscape(userID))
	req, err := http.NewRequest(http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	if km.appMetrics != nil {
		km.appMetrics.IDPMetrics().CountDeleteUser()
	}

	resp, err := km.httpClient.Do(req)
	if err != nil {
		if km.appMetrics != nil {
			km.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}
	defer resp.Body.Close() // nolint

	// In the docs, they specified 200, but in the endpoints, they return 204
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		if km.appMetrics != nil {
			km.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return fmt.Errorf("unable to delete user, statusCode %d", resp.StatusCode)
	}

	return nil
}

func (km *KeycloakManager) fetchAllUserProfiles() ([]keycloakProfile, error) {
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

	profiles := make([]keycloakProfile, 0)
	err = km.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	return profiles, nil
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

// userData construct user data from keycloak profile.
func (kp keycloakProfile) userData() *UserData {
	return &UserData{
		Email: kp.Email,
		Name:  kp.Username,
		ID:    kp.ID,
	}
}
