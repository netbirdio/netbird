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

// zitadelProfile represents an zitadel user profile response.
type zitadelProfile struct {
	ID                 string       `json:"id"`
	State              string       `json:"state"`
	UserName           string       `json:"userName"`
	PreferredLoginName string       `json:"preferredLoginName"`
	LoginNames         []string     `json:"loginNames"`
	Human              *zitadelUser `json:"human"`
}

// zitadelUserDetails represents the metadata for the new user that was created
type zitadelUserDetails struct {
	Sequence      string `json:"sequence"`     // uint64 as a string
	CreationDate  string `json:"creationDate"` // ISO format
	ChangeDate    string `json:"changeDate"`   // ISO format
	ResourceOwner string
}

// zitadelPasswordlessRegistration represents the information for the user to complete signup
type zitadelPasswordlessRegistration struct {
	Link       string `json:"link"`
	Expiration string `json:"expiration"` // ex: 3600s
}

// zitadelUser represents an zitadel create user response
type zitadelUserResponse struct {
	UserId                   string                          `json:"userId"`
	Details                  zitadelUserDetails              `json:"details"`
	PasswordlessRegistration zitadelPasswordlessRegistration `json:"passwordlessRegistration"`
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

	if config.ClientID == "" {
		return nil, fmt.Errorf("zitadel IdP configuration is incomplete, clientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("zitadel IdP configuration is incomplete, ClientSecret is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("zitadel IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.ManagementEndpoint == "" {
		return nil, fmt.Errorf("zitadel IdP configuration is incomplete, ManagementEndpoint is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("zitadel IdP configuration is incomplete, GrantType is missing")
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
	data.Set("scope", "openid urn:zitadel:iam:org:project:id:zitadel:aud")

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

// CreateUser creates a new user in zitadel Idp and sends an invite via Zitadel.
func (zm *ZitadelManager) CreateUser(email, name, accountID, invitedByEmail string) (*UserData, error) {
	firstLast := strings.SplitN(name, " ", 2)

	var addUser = map[string]any{
		"userName": email,
		"profile": map[string]string{
			"firstName":   firstLast[0],
			"lastName":    firstLast[0],
			"displayName": name,
		},
		"email": map[string]any{
			"email":           email,
			"isEmailVerified": false,
		},
		"passwordChangeRequired":          true,
		"requestPasswordlessRegistration": false, // let Zitadel send the invite for us
	}

	payload, err := zm.helper.Marshal(addUser)
	if err != nil {
		return nil, err
	}

	body, err := zm.post("users/human/_import", string(payload))
	if err != nil {
		return nil, err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountCreateUser()
	}

	var newUser zitadelUserResponse
	err = zm.helper.Unmarshal(body, &newUser)
	if err != nil {
		return nil, err
	}

	var pending bool = true
	ret := &UserData{
		Email: email,
		Name:  name,
		ID:    newUser.UserId,
		AppMetadata: AppMetadata{
			WTAccountID:     accountID,
			WTPendingInvite: &pending,
			WTInvitedBy:     invitedByEmail,
		},
	}
	return ret, nil
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

	userData := profile.User.userData()
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetAccount returns all the users for a given profile.
func (zm *ZitadelManager) GetAccount(accountID string) ([]*UserData, error) {
	body, err := zm.post("users/_search", "")
	if err != nil {
		return nil, err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountGetAccount()
	}

	var profiles struct{ Result []zitadelProfile }
	err = zm.helper.Unmarshal(body, &profiles)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	for _, profile := range profiles.Result {
		userData := profile.userData()
		userData.AppMetadata.WTAccountID = accountID

		users = append(users, userData)
	}

	return users, nil
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
		userData := profile.userData()
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], userData)
	}

	return indexedUsers, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
// Metadata values are base64 encoded.
func (zm *ZitadelManager) UpdateUserAppMetadata(_ string, _ AppMetadata) error {
	return nil
}

type inviteUserRequest struct {
	Email string `json:"email"`
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (zm *ZitadelManager) InviteUserByID(userID string) error {
	inviteUser := inviteUserRequest{
		Email: userID,
	}

	payload, err := zm.helper.Marshal(inviteUser)
	if err != nil {
		return err
	}

	// don't care about the body in the response
	_, err = zm.post(fmt.Sprintf("users/%s/_resend_initialization", userID), string(payload))
	return err
}

// DeleteUser from Zitadel
func (zm *ZitadelManager) DeleteUser(userID string) error {
	resource := fmt.Sprintf("users/%s", userID)
	if err := zm.delete(resource); err != nil {
		return err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	return nil
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

// delete perform Delete requests.
func (zm *ZitadelManager) delete(resource string) error {
	jwtToken, err := zm.credentials.Authenticate()
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/%s", zm.managementEndpoint, resource)
	req, err := http.NewRequest(http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	resp, err := zm.httpClient.Do(req)
	if err != nil {
		if zm.appMetrics != nil {
			zm.appMetrics.IDPMetrics().CountRequestError()
		}

		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if zm.appMetrics != nil {
			zm.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return fmt.Errorf("unable to get %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return nil
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

// userData construct user data from zitadel profile.
func (zp zitadelProfile) userData() *UserData {
	var (
		email string
		name  string
	)

	// Obtain the email for the human account and the login name,
	// for the machine account.
	if zp.Human != nil {
		email = zp.Human.Email.Email
		name = zp.Human.Profile.DisplayName
	} else if len(zp.LoginNames) > 0 {
		email = zp.LoginNames[0]
		name = zp.LoginNames[0]
	}

	return &UserData{
		Email: email,
		Name:  name,
		ID:    zp.ID,
	}
}
