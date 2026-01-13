package idp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

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
	useV2API           bool // Automatically detected from endpoint
}

// ZitadelClientConfig zitadel manager client configurations.
type ZitadelClientConfig struct {
	ClientID           string
	ClientSecret       string
	GrantType          string
	TokenEndpoint      string
	ManagementEndpoint string
	PAT                string
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
	IsEmailVerified bool   `json:"isEmailVerified"` // v1
	IsVerified      bool   `json:"isVerified"`      // v2
}

// zitadelUserInfo specifies user information.
type zitadelUserInfo struct {
	FirstName   string `json:"firstName"`  // v1
	LastName    string `json:"lastName"`   // v1
	GivenName   string `json:"givenName"`  // v2
	FamilyName  string `json:"familyName"` // v2
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
	ID                 string       `json:"id"`     // v1
	UserID             string       `json:"userId"` // v2
	State              string       `json:"state"`
	UserName           string       `json:"userName"`
	PreferredLoginName string       `json:"preferredLoginName"`
	LoginNames         []string     `json:"loginNames"`
	Human              *zitadelUser `json:"human"`
}

// zitadelUserDetails represents the metadata for the new user that was created
type zitadelUserDetails struct {
	Sequence      string `json:"sequence"`
	CreationDate  string `json:"creationDate"`
	ChangeDate    string `json:"changeDate"`
	ResourceOwner string `json:"resourceOwner"`
}

// zitadelPasswordlessRegistration represents the information for the user to complete signup (v1)
type zitadelPasswordlessRegistration struct {
	Link       string `json:"link"`
	Expiration string `json:"expiration"`
}

// zitadelUserResponse represents an zitadel create user response
type zitadelUserResponse struct {
	UserId                   string                           `json:"userId"`
	Details                  zitadelUserDetails               `json:"details"`
	PasswordlessRegistration *zitadelPasswordlessRegistration `json:"passwordlessRegistration"` // v1
	EmailCode                string                           `json:"emailCode"`                // v2
	PhoneCode                string                           `json:"phoneCode"`                // v2
}

// readZitadelError parses errors returned by the zitadel APIs from a response.
func readZitadelError(body io.ReadCloser) error {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	helper := JsonParser{}
	var target map[string]interface{}
	err = helper.Unmarshal(bodyBytes, &target)
	if err != nil {
		return fmt.Errorf("error unparsable body: %s", string(bodyBytes))
	}

	errorKeys := make([]string, 0, len(target))
	for k := range target {
		errorKeys = append(errorKeys, k)
	}
	slices.Sort(errorKeys)

	var errsOut []string
	for _, k := range errorKeys {
		if _, isEmbedded := target[k].(map[string]interface{}); isEmbedded {
			continue
		}
		errsOut = append(errsOut, fmt.Sprintf("%s: %v", k, target[k]))
	}

	if len(errsOut) == 0 {
		return errors.New("unknown error")
	}

	return errors.New(strings.Join(errsOut, " "))
}

// verifyJWTConfig ensures necessary values are set in the ZitadelClientConfig for JWTs to be generated.
func verifyJWTConfig(config ZitadelClientConfig) error {
	if config.ClientID == "" {
		return fmt.Errorf("zitadel IdP configuration is incomplete, clientID is missing")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("zitadel IdP configuration is incomplete, ClientSecret is missing")
	}
	if config.TokenEndpoint == "" {
		return fmt.Errorf("zitadel IdP configuration is incomplete, TokenEndpoint is missing")
	}
	if config.GrantType == "" {
		return fmt.Errorf("zitadel IdP configuration is incomplete, GrantType is missing")
	}
	return nil
}

// detectAPIVersion detects whether to use v1 or v2 API based on the management endpoint
func detectAPIVersion(endpoint string) bool {
	// Check if endpoint contains "/v2" or ends with "/v2"
	// v2 endpoints: https://example.com/v2 or https://example.com/v2/...
	// v1 endpoints: https://example.com/management/v1 or similar
	endpoint = strings.TrimSuffix(endpoint, "/")

	// Check if it contains "/v2" (but not "/v2/something" in the middle of a longer path)
	parts := strings.Split(endpoint, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "v2" {
			return true
		}
		// Stop if we find "management" or "v1" - clearly a v1 endpoint
		if parts[i] == "management" || parts[i] == "v1" {
			return false
		}
	}

	return false
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

	hasPAT := config.PAT != ""
	if !hasPAT {
		jwtErr := verifyJWTConfig(config)
		if jwtErr != nil {
			return nil, jwtErr
		}
	}

	if config.ManagementEndpoint == "" {
		return nil, fmt.Errorf("zitadel IdP configuration is incomplete, ManagementEndpoint is missing")
	}

	credentials := &ZitadelCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	// Automatically detect API version from endpoint
	useV2API := detectAPIVersion(config.ManagementEndpoint)

	return &ZitadelManager{
		managementEndpoint: config.ManagementEndpoint,
		httpClient:         httpClient,
		credentials:        credentials,
		helper:             helper,
		appMetrics:         appMetrics,
		useV2API:           useV2API,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from zitadel.
func (zc *ZitadelCredentials) jwtStillValid() bool {
	return !zc.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(zc.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
func (zc *ZitadelCredentials) requestJWTToken(ctx context.Context) (*http.Response, error) {
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

	log.WithContext(ctx).Debug("requesting new jwt token for zitadel idp manager")

	resp, err := zc.httpClient.Do(req)
	if err != nil {
		if zc.appMetrics != nil {
			zc.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		zErr := readZitadelError(resp.Body)
		return nil, fmt.Errorf("unable to get zitadel token, statusCode %d, zitadel: %w", resp.StatusCode, zErr)
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

	data, err := base64.RawURLEncoding.DecodeString(strings.Split(jwtToken.AccessToken, ".")[1])
	if err != nil {
		return jwtToken, err
	}

	var IssuedAt struct{ Exp int64 }
	err = zc.helper.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

// generatePATToken creates a functional JWTToken instance which will pass the
// PAT to the API directly and skip requesting a token.
func (zc *ZitadelCredentials) generatePATToken() (JWTToken, error) {
	tok := JWTToken{
		AccessToken: zc.clientConfig.PAT,
		Scope:       "openid",
		ExpiresIn:   9999,
		TokenType:   "PAT",
	}
	tok.expiresInTime = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	zc.jwtToken = tok
	return tok, nil
}

// Authenticate retrieves access token to use the Zitadel Management API.
func (zc *ZitadelCredentials) Authenticate(ctx context.Context) (JWTToken, error) {
	zc.mux.Lock()
	defer zc.mux.Unlock()

	if zc.appMetrics != nil {
		zc.appMetrics.IDPMetrics().CountAuthenticate()
	}

	if zc.jwtStillValid() {
		return zc.jwtToken, nil
	}

	if zc.clientConfig.PAT != "" {
		return zc.generatePATToken()
	}

	resp, err := zc.requestJWTToken(ctx)
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
func (zm *ZitadelManager) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	firstLast := strings.SplitN(name, " ", 2)
	lastName := firstLast[0]
	if len(firstLast) > 1 {
		lastName = firstLast[1]
	}

	var addUser map[string]any
	var endpoint string

	if zm.useV2API {
		// v2 API
		addUser = map[string]any{
			"userName": email,
			"profile": map[string]string{
				"givenName":   firstLast[0],
				"familyName":  lastName,
				"displayName": name,
			},
			"email": map[string]any{
				"email":      email,
				"isVerified": false,
			},
		}
		endpoint = "users/human"
	} else {
		// v1 API
		addUser = map[string]any{
			"userName": email,
			"profile": map[string]string{
				"firstName":   firstLast[0],
				"lastName":    lastName,
				"displayName": name,
			},
			"email": map[string]any{
				"email":           email,
				"isEmailVerified": false,
			},
			"passwordChangeRequired":          true,
			"requestPasswordlessRegistration": false,
		}
		endpoint = "users/human/_import"
	}

	payload, err := zm.helper.Marshal(addUser)
	if err != nil {
		return nil, err
	}

	body, err := zm.post(ctx, endpoint, string(payload))
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

	pending := true
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
func (zm *ZitadelManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
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

	endpoint := "users/_search"
	if zm.useV2API {
		endpoint = "users"
	}

	body, err := zm.post(ctx, endpoint, string(payload))
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
func (zm *ZitadelManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	body, err := zm.get(ctx, "users/"+userID, nil)
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
func (zm *ZitadelManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	endpoint := "users/_search"
	if zm.useV2API {
		endpoint = "users"
	}

	body, err := zm.post(ctx, endpoint, "")
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
func (zm *ZitadelManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	endpoint := "users/_search"
	if zm.useV2API {
		endpoint = "users"
	}

	body, err := zm.post(ctx, endpoint, "")
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
func (zm *ZitadelManager) UpdateUserAppMetadata(_ context.Context, _ string, _ AppMetadata) error {
	return nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (zm *ZitadelManager) InviteUserByID(ctx context.Context, userID string) error {
	var endpoint string
	var payload string

	if zm.useV2API {
		endpoint = fmt.Sprintf("users/%s/invite_code/resend", userID)
		payload = "{}"
	} else {
		endpoint = fmt.Sprintf("users/%s/_resend_initialization", userID)
		inviteUser := map[string]string{"email": userID}
		payloadBytes, err := zm.helper.Marshal(inviteUser)
		if err != nil {
			return err
		}
		payload = string(payloadBytes)
	}

	_, err := zm.post(ctx, endpoint, payload)
	return err
}

// DeleteUser from Zitadel
func (zm *ZitadelManager) DeleteUser(ctx context.Context, userID string) error {
	resource := fmt.Sprintf("users/%s", userID)
	if err := zm.delete(ctx, resource); err != nil {
		return err
	}

	if zm.appMetrics != nil {
		zm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	return nil
}

// post perform Post requests.
func (zm *ZitadelManager) post(ctx context.Context, resource string, body string) ([]byte, error) {
	jwtToken, err := zm.credentials.Authenticate(ctx)
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
		zErr := readZitadelError(resp.Body)
		return nil, fmt.Errorf("unable to post %s, statusCode %d, zitadel: %w", reqURL, resp.StatusCode, zErr)
	}

	return io.ReadAll(resp.Body)
}

// delete perform Delete requests.
func (zm *ZitadelManager) delete(ctx context.Context, resource string) error {
	jwtToken, err := zm.credentials.Authenticate(ctx)
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
		return fmt.Errorf("unable to delete %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return nil
}

// get perform Get requests.
func (zm *ZitadelManager) get(ctx context.Context, resource string, q url.Values) ([]byte, error) {
	jwtToken, err := zm.credentials.Authenticate(ctx)
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
		zErr := readZitadelError(resp.Body)
		return nil, fmt.Errorf("unable to get %s, statusCode %d, zitadel: %w", reqURL, resp.StatusCode, zErr)
	}

	return io.ReadAll(resp.Body)
}

// userData construct user data from zitadel profile.
func (zp zitadelProfile) userData() *UserData {
	var (
		email string
		name  string
		id    string
	)

	// Get ID - try v2 field first, then v1
	if zp.UserID != "" {
		id = zp.UserID
	} else {
		id = zp.ID
	}

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
		ID:    id,
	}
}
