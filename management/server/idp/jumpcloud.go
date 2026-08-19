package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	jumpCloudDefaultApiUrl  = "https://console.jumpcloud.com"
	jumpCloudSearchPageSize = 100
)

// jumpCloudUser represents a JumpCloud V1 API system user.
type jumpCloudUser struct {
	ID         string `json:"_id"`
	Email      string `json:"email"`
	Firstname  string `json:"firstname"`
	Middlename string `json:"middlename"`
	Lastname   string `json:"lastname"`
}

// jumpCloudUserList represents the response from the JumpCloud search endpoint.
type jumpCloudUserList struct {
	Results    []jumpCloudUser `json:"results"`
	TotalCount int             `json:"totalCount"`
}

// JumpCloudManager JumpCloud manager client instance.
type JumpCloudManager struct {
	apiBase     string
	apiToken    string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// JumpCloudClientConfig JumpCloud manager client configurations.
type JumpCloudClientConfig struct {
	APIToken string
	ApiUrl   string
}

// JumpCloudCredentials JumpCloud authentication information.
type JumpCloudCredentials struct {
	clientConfig JumpCloudClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	appMetrics   telemetry.AppMetrics
}

// NewJumpCloudManager creates a new instance of the JumpCloudManager.
func NewJumpCloudManager(config JumpCloudClientConfig, appMetrics telemetry.AppMetrics) (*JumpCloudManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   idpTimeout(),
		Transport: httpTransport,
	}

	helper := JsonParser{}

	if config.APIToken == "" {
		return nil, fmt.Errorf("jumpCloud IdP configuration is incomplete, ApiToken is missing")
	}

	apiBase := config.ApiUrl
	if apiBase == "" {
		apiBase = jumpCloudDefaultApiUrl
	}
	apiBase = strings.TrimSuffix(apiBase, "/")
	if !strings.HasSuffix(apiBase, "/api") {
		apiBase += "/api"
	}

	credentials := &JumpCloudCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &JumpCloudManager{
		apiBase:     apiBase,
		apiToken:    config.APIToken,
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// Authenticate retrieves access token to use the JumpCloud user API.
func (jc *JumpCloudCredentials) Authenticate(_ context.Context) (JWTToken, error) {
	return JWTToken{}, nil
}

// doRequest executes an HTTP request against the JumpCloud V1 API.
func (jm *JumpCloudManager) doRequest(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	reqURL := jm.apiBase + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-api-key", jm.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := jm.httpClient.Do(req)
	if err != nil {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("JumpCloud API request %s %s failed with status %d", method, path, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (jm *JumpCloudManager) UpdateUserAppMetadata(_ context.Context, _ string, _ AppMetadata) error {
	return nil
}

// GetUserDataByID requests user data from JumpCloud via ID.
func (jm *JumpCloudManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	body, err := jm.doRequest(ctx, http.MethodGet, "/systemusers/"+userID, nil)
	if err != nil {
		return nil, err
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	var user jumpCloudUser
	if err = jm.helper.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	userData := parseJumpCloudUser(user)
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetAccount returns all the users for a given profile.
func (jm *JumpCloudManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	allUsers, err := jm.searchAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetAccount()
	}

	users := make([]*UserData, 0, len(allUsers))
	for _, user := range allUsers {
		userData := parseJumpCloudUser(user)
		userData.AppMetadata.WTAccountID = accountID
		users = append(users, userData)
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (jm *JumpCloudManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	allUsers, err := jm.searchAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	indexedUsers := make(map[string][]*UserData)
	for _, user := range allUsers {
		userData := parseJumpCloudUser(user)
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], userData)
	}

	return indexedUsers, nil
}

// searchAllUsers paginates through all system users using limit/skip.
func (jm *JumpCloudManager) searchAllUsers(ctx context.Context) ([]jumpCloudUser, error) {
	var allUsers []jumpCloudUser

	for skip := 0; ; skip += jumpCloudSearchPageSize {
		searchReq := map[string]int{
			"limit": jumpCloudSearchPageSize,
			"skip":  skip,
		}

		payload, err := json.Marshal(searchReq)
		if err != nil {
			return nil, err
		}

		body, err := jm.doRequest(ctx, http.MethodPost, "/search/systemusers", bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}

		var userList jumpCloudUserList
		if err = jm.helper.Unmarshal(body, &userList); err != nil {
			return nil, err
		}

		allUsers = append(allUsers, userList.Results...)

		if skip+len(userList.Results) >= userList.TotalCount {
			break
		}
	}

	return allUsers, nil
}

// CreateUser creates a new user in JumpCloud Idp and sends an invitation.
func (jm *JumpCloudManager) CreateUser(_ context.Context, _, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (jm *JumpCloudManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	searchFilter := map[string]interface{}{
		"searchFilter": map[string]interface{}{
			"filter": []string{email},
			"fields": []string{"email"},
		},
	}

	payload, err := json.Marshal(searchFilter)
	if err != nil {
		return nil, err
	}

	body, err := jm.doRequest(ctx, http.MethodPost, "/search/systemusers", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	var userList jumpCloudUserList
	if err = jm.helper.Unmarshal(body, &userList); err != nil {
		return nil, err
	}

	usersData := make([]*UserData, 0, len(userList.Results))
	for _, user := range userList.Results {
		usersData = append(usersData, parseJumpCloudUser(user))
	}

	return usersData, nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (jm *JumpCloudManager) InviteUserByID(_ context.Context, _ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from jumpCloud directory
func (jm *JumpCloudManager) DeleteUser(ctx context.Context, userID string) error {
	_, err := jm.doRequest(ctx, http.MethodDelete, "/systemusers/"+userID, nil)
	if err != nil {
		return err
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	return nil
}

// parseJumpCloudUser parse JumpCloud system user returned from API V1 to UserData.
func parseJumpCloudUser(user jumpCloudUser) *UserData {
	names := []string{user.Firstname, user.Middlename, user.Lastname}
	return &UserData{
		Email: user.Email,
		Name:  strings.Join(names, " "),
		ID:    user.ID,
	}
}
