package idp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	log "github.com/sirupsen/logrus"
)

// ZitadelManager zitadel manager client instance.
type ZitadelManager struct {
	managementEndpoint string
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

// zitadelEmail specifies details of a user email.
type zitadelEmail struct {
	Email           string `json:"email"`
	IsEmailVerified bool   `json:"isEmailVerified"`
}

// zitadelUserInfo specifies user information.
type zitadelUserInfo struct {
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	DisplayName string `json:"displayName"`
}

// zitadelUser specifies profile details for user account.
type zitadelUser struct {
	UserName string          `json:"userName,omitempty"`
	Profile  zitadelUserInfo `json:"profile"`
	Email    zitadelEmail    `json:"email"`
}

type zitadelAttributes map[string][]map[string]any

// zitadelMetadata holds additional user data.
type zitadelMetadata struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// zitadelProfile represents an zitadel user profile response.
type zitadelProfile struct {
	ID                 string       `json:"id"`
	State              string       `json:"state"`
	UserName           string       `json:"userName"`
	PreferredLoginName string       `json:"preferredLoginName"`
	LoginNames         []string     `json:"loginNames"`
	Human              *zitadelUser `json:"human"`
	Metadata           []zitadelMetadata
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
		managementEndpoint: config.ManagementEndpoint,
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
	payload, err := buildZitadelCreateUserRequestPayload(email, name)
	if err != nil {
		return nil, err
	}

	body, err := zm.post("users/human/_import", payload)
	if err != nil {
		return nil, err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountCreateUser()
	}

	var result struct {
		UserID string `json:"userId"`
	}
	err = zm.helper.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	invite := true
	appMetadata := AppMetadata{
		WTAccountID:     accountID,
		WTPendingInvite: &invite,
	}

	// Add metadata to new user
	err = zm.UpdateUserAppMetadata(result.UserID, appMetadata)
	if err != nil {
		return nil, err
	}

	return zm.GetUserDataByID(result.UserID, appMetadata)
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (zm *ZitadelManager) GetUserByEmail(email string) ([]*UserData, error) {
	searchByEmail := zitadelAttributes{
		"queries": {
			{
				"emailQuery": map[string]any{
					"emailAddress": email,
					"method":       "TEXT_QUERY_METHOD_EQUALS",
				},
			},
		},
	}
	payload, err := zm.helper.Marshal(searchByEmail)
	if err != nil {
		return nil, err
	}

	body, err := zm.post("users/_search", string(payload))
	if err != nil {
		return nil, err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	var profiles struct{ Result []zitadelProfile }
	err = zm.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles.Result {
		metadata, err := zm.getUserMetadata(profile.ID)
		if err != nil {
			return nil, err
		}
		profile.Metadata = metadata

		users = append(users, profile.userData())
	}

	return users, nil
}

// GetUserDataByID requests user data from zitadel via ID.
func (zm *ZitadelManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	body, err := zm.get("users/"+userID, nil)
	if err != nil {
		return nil, err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	var profile struct{ User zitadelProfile }
	err = zm.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	metadata, err := zm.getUserMetadata(userID)
	if err != nil {
		return nil, err
	}
	profile.User.Metadata = metadata

	return profile.User.userData(), nil
}

// GetAccount returns all the users for a given profile.
func (zm *ZitadelManager) GetAccount(accountID string) ([]*UserData, error) {
	accounts, err := zm.GetAllAccounts()
	if err != nil {
		return nil, err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountGetAccount()
	}

	return accounts[accountID], nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (zm *ZitadelManager) GetAllAccounts() (map[string][]*UserData, error) {
	body, err := zm.post("users/_search", "")
	if err != nil {
		return nil, err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	var profiles struct{ Result []zitadelProfile }
	err = zm.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	for _, profile := range profiles.Result {
		// fetch user metadata
		metadata, err := zm.getUserMetadata(profile.ID)
		if err != nil {
			return nil, err
		}
		profile.Metadata = metadata

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
// Metadata values are base64 encoded.
func (zm *ZitadelManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	wtAccountIDValue := base64.StdEncoding.EncodeToString([]byte(appMetadata.WTAccountID))

	pendingInviteBuf := strconv.AppendBool([]byte{}, *appMetadata.WTPendingInvite)
	wtPendingInviteValue := base64.StdEncoding.EncodeToString(pendingInviteBuf)

	metadata := zitadelAttributes{
		"metadata": {
			{
				"key":   wtAccountID,
				"value": wtAccountIDValue,
			},
			{
				"key":   wtPendingInvite,
				"value": wtPendingInviteValue,
			},
		},
	}
	payload, err := zm.helper.Marshal(metadata)
	if err != nil {
		return err
	}

	resource := fmt.Sprintf("users/%s/metadata/_bulk", userID)
	_, err = zm.post(resource, string(payload))
	if err != nil {
		return err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	return nil
}

// getUserMetadata requests user metadata from zitadel via ID.
func (zm *ZitadelManager) getUserMetadata(userID string) ([]zitadelMetadata, error) {
	resource := fmt.Sprintf("users/%s/metadata/_search", userID)
	body, err := zm.post(resource, "")
	if err != nil {
		return nil, err
	}

	var metadata struct{ Result []zitadelMetadata }
	err = zm.helper.Unmarshal(body, &metadata)
	if err != nil {
		return nil, err
	}

	return metadata.Result, nil
}

// post perform Post requests.
func (zm *ZitadelManager) post(resource string, body string) ([]byte, error) {
	jwtToken, err := zm.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/%s", zm.managementEndpoint, resource)
	req, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	resp, err := zm.httpClient.Do(req)
	if err != nil {
		if zm.appMetrics != nil {
			zm.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		if zm.appMetrics != nil {
			zm.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return nil, fmt.Errorf("unable to post %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// get perform Get requests.
func (zm *ZitadelManager) get(resource string, q url.Values) ([]byte, error) {
	jwtToken, err := zm.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/%s?%s", zm.managementEndpoint, resource, q.Encode())
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	resp, err := zm.httpClient.Do(req)
	if err != nil {
		if zm.appMetrics != nil {
			zm.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if zm.appMetrics != nil {
			zm.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return nil, fmt.Errorf("unable to get %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// value returns string represented by the base64 string value.
func (zm zitadelMetadata) value() string {
	value, err := base64.StdEncoding.DecodeString(zm.Value)
	if err != nil {
		return ""
	}

	return string(value)
}

// userData construct user data from zitadel profile.
func (zp zitadelProfile) userData() *UserData {
	var (
		email                string
		name                 string
		wtAccountIDValue     string
		wtPendingInviteValue bool
	)

	for _, metadata := range zp.Metadata {
		if metadata.Key == wtAccountID {
			wtAccountIDValue = metadata.value()
		}

		if metadata.Key == wtPendingInvite {
			value, err := strconv.ParseBool(metadata.value())
			if err == nil {
				wtPendingInviteValue = value
			}
		}
	}

	// Obtain the email for the human account and the login name,
	// for the machine account.
	if zp.Human != nil {
		email = zp.Human.Email.Email
		name = zp.Human.Profile.DisplayName
	} else {
		if len(zp.LoginNames) > 0 {
			email = zp.LoginNames[0]
			name = zp.LoginNames[0]
		}
	}

	return &UserData{
		Email: email,
		Name:  name,
		ID:    zp.ID,
		AppMetadata: AppMetadata{
			WTAccountID:     wtAccountIDValue,
			WTPendingInvite: &wtPendingInviteValue,
		},
	}
}

func buildZitadelCreateUserRequestPayload(email string, name string) (string, error) {
	words := strings.Fields(name)
	n := len(words)

	firstName := strings.Join(words[:n-1], " ")
	lastName := words[n-1]

	req := &zitadelUser{
		UserName: name,
		Profile: zitadelUserInfo{
			FirstName:   strings.TrimSpace(firstName),
			LastName:    strings.TrimSpace(lastName),
			DisplayName: name,
		},
		Email: zitadelEmail{
			Email:           email,
			IsEmailVerified: false,
		},
	}

	str, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	return string(str), nil
}
