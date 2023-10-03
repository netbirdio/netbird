package idp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	v1 "github.com/TheJumpCloud/jcapi-go/v1"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	contentType = "application/json"
	accept      = "application/json"
)

// JumpCloudManager JumpCloud manager client instance.
type JumpCloudManager struct {
	client      *v1.APIClient
	apiToken    string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// JumpCloudClientConfig JumpCloud manager client configurations.
type JumpCloudClientConfig struct {
	APIToken string
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
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.APIToken == "" {
		return nil, fmt.Errorf("jumpCloud IdP configuration is incomplete, ApiToken is missing")
	}

	client := v1.NewAPIClient(v1.NewConfiguration())
	credentials := &JumpCloudCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &JumpCloudManager{
		client:      client,
		apiToken:    config.APIToken,
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// Authenticate retrieves access token to use the JumpCloud user API.
func (jc *JumpCloudCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

func (jm *JumpCloudManager) authenticationContext() context.Context {
	return context.WithValue(context.Background(), v1.ContextAPIKey, v1.APIKey{
		Key: jm.apiToken,
	})
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (jm *JumpCloudManager) UpdateUserAppMetadata(_ string, _ AppMetadata) error {
	return nil
}

// GetUserDataByID requests user data from JumpCloud via ID.
func (jm *JumpCloudManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	authCtx := jm.authenticationContext()
	user, resp, err := jm.client.SystemusersApi.SystemusersGet(authCtx, userID, contentType, accept, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", userID, resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	userData := parseJumpCloudUser(user)
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetAccount returns all the users for a given profile.
func (jm *JumpCloudManager) GetAccount(accountID string) ([]*UserData, error) {
	authCtx := jm.authenticationContext()
	userList, resp, err := jm.client.SearchApi.SearchSystemusersPost(authCtx, contentType, accept, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get account %s users, statusCode %d", accountID, resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetAccount()
	}

	users := make([]*UserData, 0)
	for _, user := range userList.Results {
		userData := parseJumpCloudUser(user)
		userData.AppMetadata.WTAccountID = accountID

		users = append(users, userData)
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (jm *JumpCloudManager) GetAllAccounts() (map[string][]*UserData, error) {
	authCtx := jm.authenticationContext()
	userList, resp, err := jm.client.SearchApi.SearchSystemusersPost(authCtx, contentType, accept, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get all accounts, statusCode %d", resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	indexedUsers := make(map[string][]*UserData)
	for _, user := range userList.Results {
		userData := parseJumpCloudUser(user)
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], userData)
	}

	return indexedUsers, nil
}

// CreateUser creates a new user in JumpCloud Idp and sends an invitation.
func (jm *JumpCloudManager) CreateUser(_, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (jm *JumpCloudManager) GetUserByEmail(email string) ([]*UserData, error) {
	searchFilter := map[string]interface{}{
		"searchFilter": map[string]interface{}{
			"filter": []string{email},
			"fields": []string{"email"},
		},
	}

	authCtx := jm.authenticationContext()
	userList, resp, err := jm.client.SearchApi.SearchSystemusersPost(authCtx, contentType, accept, searchFilter)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", email, resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	usersData := make([]*UserData, 0)
	for _, user := range userList.Results {
		usersData = append(usersData, parseJumpCloudUser(user))
	}

	return usersData, nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (jm *JumpCloudManager) InviteUserByID(_ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from jumpCloud directory
func (jm *JumpCloudManager) DeleteUser(userID string) error {
	authCtx := jm.authenticationContext()
	_, resp, err := jm.client.SystemusersApi.SystemusersDelete(authCtx, userID, contentType, accept, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to delete user, statusCode %d", resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	return nil
}

// parseJumpCloudUser parse JumpCloud system user returned from API V1 to UserData.
func parseJumpCloudUser(user v1.Systemuserreturn) *UserData {
	names := []string{user.Firstname, user.Middlename, user.Lastname}
	return &UserData{
		Email: user.Email,
		Name:  strings.Join(names, " "),
		ID:    user.Id,
	}
}
