package idp

import (
	"context"
	"fmt"
	v1 "github.com/TheJumpCloud/jcapi-go/v1"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"net/http"
	"strings"
	"time"
)

const (
	contentType = "application/json"
	accept      = "application/json"
)

// JumpCloudManager JumpCloud manager client instance.
type JumpCloudManager struct {
	apiV1Client *v1.APIClient
	apiToken    string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// JumpCloudClientConfig JumpCloud manager client configurations.
type JumpCloudClientConfig struct {
	APIToken      string
	TokenEndpoint string
	GrantType     string
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

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("jumpCloud IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("jumpCloud IdP configuration is incomplete, GrantType is missing")
	}

	apiV1Client := v1.NewAPIClient(v1.NewConfiguration())
	credentials := &JumpCloudCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &JumpCloudManager{
		apiV1Client: apiV1Client,
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

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (jm *JumpCloudManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	//TODO implement me
	panic("implement me")
}

// GetUserDataByID requests user data from JumpCloud via ID.
func (jm *JumpCloudManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetAccount returns all the users for a given profile.
func (jm *JumpCloudManager) GetAccount(accountID string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (jm *JumpCloudManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// CreateUser creates a new user in JumpCloud Idp and sends an invitation.
func (jm *JumpCloudManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (jm *JumpCloudManager) GetUserByEmail(email string) ([]*UserData, error) {
	auth := context.WithValue(context.Background(), v1.ContextAPIKey, v1.APIKey{
		Key: jm.apiToken,
	})
	searchFilter := map[string]interface{}{
		"searchFilter": map[string]interface{}{
			"searchTerm": email,
			"fields":     []string{"email"},
		},
	}

	usersList, resp, err := jm.apiV1Client.SearchApi.SearchSystemusersPost(auth, contentType, accept, searchFilter)
	if err != nil {
		return nil, err
	}

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
	for _, user := range usersList.Results {
		userData, err := parseV1SystemUser(user)
		if err != nil {
			return nil, err
		}
		usersData = append(usersData, userData)
	}

	return usersData, nil
}

// parseV1SystemUser parse JumpCloud system user returned from API V1 to UserData.
func parseV1SystemUser(user v1.Systemuserreturn) (*UserData, error) {
	names := []string{user.Firstname, user.Middlename, user.Lastname}

	return &UserData{
		Email:       user.Email,
		Name:        strings.Join(names, " "),
		ID:          user.Id,
		AppMetadata: AppMetadata{},
	}, nil
}
