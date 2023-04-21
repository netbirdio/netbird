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

const (
	// azure extension properties template
	wtAccountIDTpl     = "extension_%s_wt_account_id"
	wtPendingInviteTpl = "extension_%s_wt_pending_invite"

	profileFields   = "id,displayName,mail,userPrincipalName"
	extensionFields = "id,name,targetObjects"
)

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
	GraphAPIEndpoint string
	ObjectID         string
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

// passwordProfile represent authentication method for,
// newly created user profile.
type passwordProfile struct {
	ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
	Password                      string `json:"password"`
}

// azureExtension represent custom attribute,
// that can be added to user objects in Azure Active Directory (AD).
type azureExtension struct {
	Name          string   `json:"name"`
	DataType      string   `json:"dataType"`
	TargetObjects []string `json:"targetObjects"`
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

	manager := &AzureManager{
		ObjectID:         config.ObjectID,
		ClientID:         config.ClientID,
		GraphAPIEndpoint: config.GraphAPIEndpoint,
		httpClient:       httpClient,
		credentials:      credentials,
		helper:           helper,
		appMetrics:       appMetrics,
	}

	return manager, nil
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

func (am *AzureManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	payload, err := buildAzureCreateUserRequestPayload(email, name, accountID, am.ClientID)
	if err != nil {
		return nil, err
	}

	body, err := am.post("users", payload)
	if err != nil {
		return nil, err
	}

	var profile azureProfile
	err = am.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	wtAccountIDField := fmt.Sprintf(wtAccountIDTpl, am.ClientID)
	profile[wtAccountIDField] = accountID

	wtPendingInviteField := fmt.Sprintf(wtPendingInviteTpl, am.ClientID)
	profile[wtPendingInviteField] = true

	return profile.userData(am.ClientID), nil
}

func (am *AzureManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	wtAccountIDField := fmt.Sprintf(wtAccountIDTpl, am.ClientID)
	wtPendingInviteField := fmt.Sprintf(wtPendingInviteTpl, am.ClientID)
	selectFields := strings.Join([]string{profileFields, wtAccountIDField, wtPendingInviteField}, ",")

	q := url.Values{}
	q.Add("$select", selectFields)

	body, err := am.get("users/"+userID, q)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	var profile azureProfile
	err = am.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	return profile.userData(am.ClientID), nil
}

func (am *AzureManager) GetUserByEmail(email string) ([]*UserData, error) {
	wtAccountIDField := fmt.Sprintf(wtAccountIDTpl, am.ClientID)
	wtPendingInviteField := fmt.Sprintf(wtPendingInviteTpl, am.ClientID)
	selectFields := strings.Join([]string{profileFields, wtAccountIDField, wtPendingInviteField}, ",")

	q := url.Values{}
	q.Add("$select", selectFields)

	body, err := am.get("users/"+email, q)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	var profile azureProfile
	err = am.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	users = append(users, profile.userData(am.ClientID))

	return users, nil
}

func (am *AzureManager) GetAccount(accountID string) ([]*UserData, error) {
	wtAccountIDField := fmt.Sprintf(wtAccountIDTpl, am.ClientID)
	wtPendingInviteField := fmt.Sprintf(wtPendingInviteTpl, am.ClientID)
	selectFields := strings.Join([]string{profileFields, wtAccountIDField, wtPendingInviteField}, ",")

	q := url.Values{}
	q.Add("$select", selectFields)
	q.Add("$filter", fmt.Sprintf("%s eq '%s'", wtAccountIDField, accountID))

	body, err := am.get("users", q)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	var profiles struct{ Value []azureProfile }
	err = am.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles.Value {
		users = append(users, profile.userData(am.ClientID))
	}

	return users, nil
}

func (am *AzureManager) GetAllAccounts() (map[string][]*UserData, error) {
	wtAccountIDField := fmt.Sprintf(wtAccountIDTpl, am.ClientID)
	wtPendingInviteField := fmt.Sprintf(wtPendingInviteTpl, am.ClientID)
	selectFields := strings.Join([]string{profileFields, wtAccountIDField, wtPendingInviteField}, ",")

	q := url.Values{}
	q.Add("$select", selectFields)

	body, err := am.get("users", q)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	var profiles struct{ Value []azureProfile }
	err = am.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	for _, profile := range profiles.Value {
		userData := profile.userData(am.ClientID)

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

func (am *AzureManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return err
	}

	wtAccountIDField := fmt.Sprintf(wtAccountIDTpl, am.ClientID)
	wtPendingInviteField := fmt.Sprintf(wtPendingInviteTpl, am.ClientID)

	data, err := am.helper.Marshal(map[string]any{
		wtAccountIDField:     appMetadata.WTAccountID,
		wtPendingInviteField: appMetadata.WTPendingInvite,
	})
	if err != nil {
		return err
	}
	payload := strings.NewReader(string(data))

	reqURL := fmt.Sprintf("%s/users/%s", am.GraphAPIEndpoint, userID)
	req, err := http.NewRequest(http.MethodPatch, reqURL, payload)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	log.Debugf("updating idp metadata for user %s", userID)

	resp, err := am.httpClient.Do(req)
	if err != nil {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}
	defer resp.Body.Close()

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unable to update the appMetadata, statusCode %d", resp.StatusCode)
	}

	return nil
}

func (am *AzureManager) getUserExtensions() ([]azureExtension, error) {
	q := url.Values{}
	q.Add("$select", extensionFields)

	resource := fmt.Sprintf("applications/%s/extensionProperties", am.ObjectID)
	body, err := am.get(resource, q)
	if err != nil {
		return nil, err
	}

	var extensions struct{ Value []azureExtension }
	err = am.helper.Unmarshal(body, &extensions)
	if err != nil {
		return nil, err
	}

	return extensions.Value, nil
}

func (am *AzureManager) createUserExtension(name string) (*azureExtension, error) {
	extension := azureExtension{
		Name:          name,
		DataType:      "string",
		TargetObjects: []string{"User"},
	}

	payload, err := am.helper.Marshal(extension)
	if err != nil {
		return nil, err
	}

	resource := fmt.Sprintf("applications/%s/extensionProperties", am.ObjectID)
	body, err := am.post(resource, string(payload))
	if err != nil {
		return nil, err
	}

	var userExtension azureExtension
	err = am.helper.Unmarshal(body, &userExtension)
	if err != nil {
		return nil, err
	}

	return &userExtension, nil
}

// get perform Get requests.
func (am *AzureManager) get(resource string, q url.Values) ([]byte, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/%s?%s", am.GraphAPIEndpoint, resource, q.Encode())
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

// post perform Post requests.
func (am *AzureManager) post(resource string, body string) ([]byte, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/%s", am.GraphAPIEndpoint, resource)
	req, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountCreateUser()
	}

	resp, err := am.httpClient.Do(req)
	if err != nil {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return nil, fmt.Errorf("unable to get %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// userData construct user data from keycloak profile.
func (ap azureProfile) userData(clientID string) *UserData {
	id, ok := ap["id"].(string)
	if ok {
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

	accountIDField := fmt.Sprintf(wtAccountIDTpl, clientID)
	accountID, ok := ap[accountIDField].(string)
	if !ok {
		accountID = ""
	}

	pendingInviteField := fmt.Sprintf(wtPendingInviteTpl, clientID)
	pendingInvite, ok := ap[pendingInviteField].(bool)
	if !ok {
		pendingInvite = false
	}

	return &UserData{
		Email: email,
		Name:  name,
		ID:    id,
		AppMetadata: AppMetadata{
			WTAccountID:     accountID,
			WTPendingInvite: &pendingInvite,
		},
	}
}

func buildAzureCreateUserRequestPayload(email, name, accountID, clientID string) (string, error) {
	wtAccountIDField := fmt.Sprintf(wtAccountIDTpl, clientID)
	wtPendingInviteField := fmt.Sprintf(wtPendingInviteTpl, clientID)

	req := &azureProfile{
		"accountEnabled":    true,
		"displayName":       name,
		"mailNickName":      strings.Join(strings.Split(name, " "), ""),
		"userPrincipalName": email,
		"passwordProfile": passwordProfile{
			ForceChangePasswordNextSignIn: true,
			Password:                      GeneratePassword(8, 1, 1, 1),
		},
		wtAccountIDField:     accountID,
		wtPendingInviteField: true,
	}

	str, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

// hasExtension checks whether a given extension by name,
// exists in an list of extensions.
func hasExtension(extensions []azureExtension, name string) bool {
	for _, ext := range extensions {
		if ext.Name == name {
			return true
		}
	}
	return false
}
