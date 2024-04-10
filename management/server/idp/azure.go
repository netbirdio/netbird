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
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

const profileFields = "id,displayName,mail,userPrincipalName"

// AzureManager azure manager client instance.
type AzureManager struct {
	ClientID         string
	ObjectID         string
	GraphAPIEndpoint string
	httpClient       ManagerHTTPClient
	credentials      ManagerCredentials
	helper           ManagerHelper
	appMetrics       telemetry.AppMetrics
}

// AzureClientConfig azure manager client configurations.
type AzureClientConfig struct {
	ClientID         string
	ClientSecret     string
	ObjectID         string
	GraphAPIEndpoint string
	TokenEndpoint    string
	GrantType        string
}

// AzureCredentials azure authentication information.
type AzureCredentials struct {
	clientConfig AzureClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// azureProfile represents an azure user profile.
type azureProfile map[string]any

// NewAzureManager creates a new instance of the AzureManager.
func NewAzureManager(config AzureClientConfig, appMetrics telemetry.AppMetrics) (*AzureManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.ClientID == "" {
		return nil, fmt.Errorf("azure IdP configuration is incomplete, clientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("azure IdP configuration is incomplete, ClientSecret is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("azure IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.GraphAPIEndpoint == "" {
		return nil, fmt.Errorf("azure IdP configuration is incomplete, GraphAPIEndpoint is missing")
	}

	if config.ObjectID == "" {
		return nil, fmt.Errorf("azure IdP configuration is incomplete, ObjectID is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("azure IdP configuration is incomplete, GrantType is missing")
	}

	credentials := &AzureCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &AzureManager{
		ObjectID:         config.ObjectID,
		ClientID:         config.ClientID,
		GraphAPIEndpoint: config.GraphAPIEndpoint,
		httpClient:       httpClient,
		credentials:      credentials,
		helper:           helper,
		appMetrics:       appMetrics,
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
	parsedURL, err := url.Parse(ac.clientConfig.GraphAPIEndpoint)
	if err != nil {
		return nil, err
	}

	// get base url and add "/.default" as scope
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host
	scopeURL := baseURL + "/.default"
	data.Set("scope", scopeURL)

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

// CreateUser creates a new user in azure AD Idp.
func (am *AzureManager) CreateUser(_, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// GetUserDataByID requests user data from keycloak via ID.
func (am *AzureManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	q := url.Values{}
	q.Add("$select", profileFields)

	body, err := am.get("users/"+userID, q)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	var profile azureProfile
	err = am.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	userData := profile.userData()
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (am *AzureManager) GetUserByEmail(email string) ([]*UserData, error) {
	q := url.Values{}
	q.Add("$select", profileFields)

	body, err := am.get("users/"+email, q)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	var profile azureProfile
	err = am.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	users = append(users, profile.userData())

	return users, nil
}

// GetAccount returns all the users for a given profile.
func (am *AzureManager) GetAccount(accountID string) ([]*UserData, error) {
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
func (am *AzureManager) GetAllAccounts() (map[string][]*UserData, error) {
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

// UpdateUserAppMetadata updates user app metadata based on userID.
func (am *AzureManager) UpdateUserAppMetadata(_ string, _ AppMetadata) error {
	return nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (am *AzureManager) InviteUserByID(_ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from Azure.
func (am *AzureManager) DeleteUser(userID string) error {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/users/%s", am.GraphAPIEndpoint, url.QueryEscape(userID))
	req, err := http.NewRequest(http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	log.Debugf("delete idp user %s", userID)

	resp, err := am.httpClient.Do(req)
	if err != nil {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}
	defer resp.Body.Close()

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountDeleteUser()
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unable to delete user, statusCode %d", resp.StatusCode)
	}

	return nil
}

// getAllUsers returns all users in an Azure AD account.
func (am *AzureManager) getAllUsers() ([]*UserData, error) {
	users := make([]*UserData, 0)

	q := url.Values{}
	q.Add("$select", profileFields)
	q.Add("$top", "500")

	for nextLink := "users"; nextLink != ""; {
		body, err := am.get(nextLink, q)
		if err != nil {
			return nil, err
		}

		var profiles struct {
			Value    []azureProfile
			NextLink string `json:"@odata.nextLink"`
		}
		err = am.helper.Unmarshal(body, &profiles)
		if err != nil {
			return nil, err
		}

		for _, profile := range profiles.Value {
			users = append(users, profile.userData())
		}

		nextLink = profiles.NextLink
	}

	return users, nil
}

// get perform Get requests.
func (am *AzureManager) get(resource string, q url.Values) ([]byte, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	var reqURL string
	if strings.HasPrefix(resource, "https") {
		// Already an absolute URL for paging
		reqURL = resource
	} else {
		reqURL = fmt.Sprintf("%s/%s?%s", am.GraphAPIEndpoint, resource, q.Encode())
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	resp, err := am.httpClient.Do(req)
	if err != nil {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return nil, fmt.Errorf("unable to get %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// userData construct user data from keycloak profile.
func (ap azureProfile) userData() *UserData {
	id, ok := ap["id"].(string)
	if !ok {
		id = ""
	}

	email, ok := ap["userPrincipalName"].(string)
	if !ok {
		email = ""
	}

	name, ok := ap["displayName"].(string)
	if !ok {
		name = ""
	}

	return &UserData{
		Email: email,
		Name:  name,
		ID:    id,
	}
}
