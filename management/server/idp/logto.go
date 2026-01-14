package idp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// LogtoManager logto manager client instance.
type LogtoManager struct {
	managementEndpoint string
	httpClient         ManagerHTTPClient
	credentials        ManagerCredentials
	helper             ManagerHelper
	appMetrics         telemetry.AppMetrics
}

// LogtoClientConfig logto manager client configurations.
type LogtoClientConfig struct {
	ClientID           string
	ClientSecret       string
	GrantType          string
	TokenEndpoint      string
	ManagementEndpoint string
	Resource           string // Required: https://{tenant-id}.logto.app/api
	TenantID           string // Tenant ID (Cloud) or "default" (OSS)
}

// LogtoCredentials logto authentication information.
type LogtoCredentials struct {
	clientConfig LogtoClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// logtoProfile represents a logto user profile response.
type logtoProfile struct {
	ID           string           `json:"id"`
	Username     string           `json:"username"`
	PrimaryEmail string           `json:"primaryEmail"`
	PrimaryPhone string           `json:"primaryPhone,omitempty"`
	Name         string           `json:"name"`
	Avatar       string           `json:"avatar,omitempty"`
	CustomData   interface{}      `json:"customData,omitempty"`
	Profile      logtoUserProfile `json:"profile,omitempty"`
	CreatedAt    float64          `json:"createdAt,omitempty"`
	UpdatedAt    float64          `json:"updatedAt,omitempty"`
	LastSignInAt float64          `json:"lastSignInAt,omitempty"`
	IsSuspended  bool             `json:"isSuspended,omitempty"`
	HasPassword  bool             `json:"hasPassword,omitempty"`
}

// logtoUserProfile represents the nested profile object in LogTo user.
type logtoUserProfile struct {
	FamilyName        string `json:"familyName,omitempty"`
	GivenName         string `json:"givenName,omitempty"`
	MiddleName        string `json:"middleName,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferredUsername,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Website           string `json:"website,omitempty"`
	Gender            string `json:"gender,omitempty"`
	Birthdate         string `json:"birthdate,omitempty"`
	Zoneinfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
}

// NewLogtoManager creates a new instance of the LogtoManager.
func NewLogtoManager(config LogtoClientConfig, appMetrics telemetry.AppMetrics) (*LogtoManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.ClientID == "" {
		return nil, fmt.Errorf("logto IdP configuration is incomplete, clientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("logto IdP configuration is incomplete, ClientSecret is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("logto IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.ManagementEndpoint == "" {
		return nil, fmt.Errorf("logto IdP configuration is incomplete, ManagementEndpoint is missing")
	}

	if config.Resource == "" {
		return nil, fmt.Errorf("logto IdP configuration is incomplete, Resource is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("logto IdP configuration is incomplete, GrantType is missing")
	}

	credentials := &LogtoCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &LogtoManager{
		managementEndpoint: config.ManagementEndpoint,
		httpClient:         httpClient,
		credentials:        credentials,
		helper:             helper,
		appMetrics:         appMetrics,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from logto.
func (lc *LogtoCredentials) jwtStillValid() bool {
	return !lc.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(lc.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token.
// LogTo uses Basic Authentication in header (not client_id/client_secret in body like Keycloak).
func (lc *LogtoCredentials) requestJWTToken(ctx context.Context) (*http.Response, error) {
	// Basic auth: base64(appId:appSecret)
	auth := base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%s", lc.clientConfig.ClientID, lc.clientConfig.ClientSecret)),
	)

	data := url.Values{}
	data.Set("grant_type", lc.clientConfig.GrantType)
	data.Set("resource", lc.clientConfig.Resource) // Required parameter for LogTo
	data.Set("scope", "all")

	payload := strings.NewReader(data.Encode())
	req, err := http.NewRequest(http.MethodPost, lc.clientConfig.TokenEndpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Basic "+auth) // Basic auth in header
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	log.WithContext(ctx).Debug("requesting new jwt token for logto idp manager")

	resp, err := lc.httpClient.Do(req)
	if err != nil {
		if lc.appMetrics != nil {
			lc.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if lc.appMetrics != nil {
			lc.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get logto token, statusCode %d", resp.StatusCode)
	}

	return resp, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds.
func (lc *LogtoCredentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := io.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = lc.helper.Unmarshal(body, &jwtToken)
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

	// Exp maps into exp from jwt token
	var IssuedAt struct{ Exp int64 }
	err = lc.helper.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

// Authenticate retrieves access token to use the LogTo Management API.
func (lc *LogtoCredentials) Authenticate(ctx context.Context) (JWTToken, error) {
	lc.mux.Lock()
	defer lc.mux.Unlock()

	if lc.appMetrics != nil {
		lc.appMetrics.IDPMetrics().CountAuthenticate()
	}

	// reuse the token without requesting a new one if it is not expired,
	// and if expiry time is sufficient time available to make a request.
	if lc.jwtStillValid() {
		return lc.jwtToken, nil
	}

	resp, err := lc.requestJWTToken(ctx)
	if err != nil {
		return lc.jwtToken, err
	}
	defer resp.Body.Close()

	jwtToken, err := lc.parseRequestJWTResponse(resp.Body)
	if err != nil {
		return lc.jwtToken, err
	}

	lc.jwtToken = jwtToken

	return lc.jwtToken, nil
}

// CreateUser creates a new user in logto Idp.
func (lm *LogtoManager) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	// Split name into first and last name
	firstLast := strings.SplitN(name, " ", 2)
	givenName := firstLast[0]
	familyName := givenName
	if len(firstLast) > 1 {
		familyName = firstLast[1]
	}

	// LogTo user creation payload - using profile structure with givenName and familyName
	createUser := map[string]any{
		"primaryEmail": email,
		"name":         name,
		"username":     email, // Use email as username
		"profile": map[string]string{
			"givenName":  givenName,
			"familyName": familyName,
		},
	}

	payload, err := lm.helper.Marshal(createUser)
	if err != nil {
		return nil, err
	}

	body, err := lm.post(ctx, "users", string(payload))
	if err != nil {
		return nil, err
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountCreateUser()
	}

	var newUser logtoProfile
	err = lm.helper.Unmarshal(body, &newUser)
	if err != nil {
		return nil, err
	}

	var pending bool = true
	ret := &UserData{
		Email: email,
		Name:  name,
		ID:    newUser.ID,
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
func (lm *LogtoManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	q := url.Values{}
	q.Add("search", email)
	q.Add("exact", "true")

	body, err := lm.get(ctx, "users", q)
	if err != nil {
		return nil, err
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	// LogTo returns paginated response, check if it's wrapped in a data field
	var response struct {
		Data []logtoProfile `json:"data"`
	}
	err = lm.helper.Unmarshal(body, &response)
	if err != nil {
		// Try direct array format
		profiles := make([]logtoProfile, 0)
		err2 := lm.helper.Unmarshal(body, &profiles)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse logto user response: %w", err)
		}
		users := make([]*UserData, 0)
		for _, profile := range profiles {
			users = append(users, profile.userData())
		}
		return users, nil
	}

	users := make([]*UserData, 0)
	for _, profile := range response.Data {
		users = append(users, profile.userData())
	}

	return users, nil
}

// GetUserDataByID requests user data from logto via ID.
func (lm *LogtoManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	body, err := lm.get(ctx, "users/"+userID, nil)
	if err != nil {
		return nil, err
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	var profile logtoProfile
	err = lm.helper.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	userData := profile.userData()
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetAccount returns all the users for a given account profile.
func (lm *LogtoManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	profiles, err := lm.fetchAllUserProfiles(ctx)
	if err != nil {
		return nil, err
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetAccount()
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
func (lm *LogtoManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	profiles, err := lm.fetchAllUserProfiles(ctx)
	if err != nil {
		return nil, err
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	indexedUsers := make(map[string][]*UserData)
	for _, profile := range profiles {
		userData := profile.userData()
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], userData)
	}

	return indexedUsers, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (lm *LogtoManager) UpdateUserAppMetadata(_ context.Context, _ string, _ AppMetadata) error {
	// LogTo may not support custom app metadata
	return nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (lm *LogtoManager) InviteUserByID(_ context.Context, _ string) error {
	return fmt.Errorf("method InviteUserByID not implemented for LogTo")
}

// DeleteUser from LogTo by user ID.
func (lm *LogtoManager) DeleteUser(ctx context.Context, userID string) error {
	jwtToken, err := lm.credentials.Authenticate(ctx)
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/users/%s", lm.managementEndpoint, url.QueryEscape(userID))
	req, err := http.NewRequest(http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	resp, err := lm.httpClient.Do(req)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}
	defer resp.Body.Close()

	// LogTo typically returns 204 No Content for successful deletions
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return fmt.Errorf("unable to delete user, statusCode %d", resp.StatusCode)
	}

	return nil
}

// fetchAllUserProfiles fetches all user profiles with pagination.
func (lm *LogtoManager) fetchAllUserProfiles(ctx context.Context) ([]logtoProfile, error) {
	profiles := make([]logtoProfile, 0)
	page := 1
	pageSize := 100 // Use larger page size for efficiency

	for {
		q := url.Values{}
		q.Add("page", strconv.Itoa(page))
		q.Add("page_size", strconv.Itoa(pageSize))

		body, err := lm.get(ctx, "users", q)
		if err != nil {
			return nil, err
		}

		// LogTo returns paginated response, check if it's wrapped in a data field
		var response struct {
			Data []logtoProfile `json:"data"`
		}
		err = lm.helper.Unmarshal(body, &response)
		if err != nil {
			// Try direct array format
			pageProfiles := make([]logtoProfile, 0)
			err2 := lm.helper.Unmarshal(body, &pageProfiles)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse logto user response: %w", err)
			}
			profiles = append(profiles, pageProfiles...)
			// Check if more pages exist
			if len(pageProfiles) < pageSize {
				break
			}
		} else {
			profiles = append(profiles, response.Data...)
			// Check if more pages exist
			if len(response.Data) < pageSize {
				break
			}
		}
		page++
	}

	return profiles, nil
}

// get perform Get requests.
func (lm *LogtoManager) get(ctx context.Context, resource string, q url.Values) ([]byte, error) {
	jwtToken, err := lm.credentials.Authenticate(ctx)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/%s", lm.managementEndpoint, resource)
	if q != nil && len(q) > 0 {
		reqURL += "?" + q.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	resp, err := lm.httpClient.Do(req)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		return nil, fmt.Errorf("unable to get %s, statusCode %d", reqURL, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// post perform Post requests.
func (lm *LogtoManager) post(ctx context.Context, resource string, body string) ([]byte, error) {
	jwtToken, err := lm.credentials.Authenticate(ctx)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/%s", lm.managementEndpoint, resource)
	req, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	resp, err := lm.httpClient.Do(req)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}

		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestStatusError()
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unable to post %s, statusCode %d, response: %s", reqURL, resp.StatusCode, string(bodyBytes))
	}

	return io.ReadAll(resp.Body)
}

// userData construct user data from logto profile.
func (lp logtoProfile) userData() *UserData {
	// Use name field if available, otherwise construct from profile
	displayName := lp.Name
	if displayName == "" && lp.Profile.GivenName != "" {
		if lp.Profile.FamilyName != "" {
			displayName = lp.Profile.GivenName + " " + lp.Profile.FamilyName
		} else {
			displayName = lp.Profile.GivenName
		}
	}
	// Fallback to username if name is still empty
	if displayName == "" {
		displayName = lp.Username
	}

	return &UserData{
		Email: lp.PrimaryEmail,
		Name:  displayName,
		ID:    lp.ID,
	}
}
