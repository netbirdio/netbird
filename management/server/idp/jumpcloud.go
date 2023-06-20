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

type JumpCloudAttribute struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
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
	authCtx := context.WithValue(context.Background(), v1.ContextAPIKey, v1.APIKey{
		Key: jm.apiToken,
	})
	updateReq := map[string]any{
		"body": v1.Systemuserput{
			Attributes: []interface{}{
				JumpCloudAttribute{
					Name:  "wtAccountID",
					Value: appMetadata.WTAccountID,
				},
				JumpCloudAttribute{
					Name:  "wtPendingInvite",
					Value: appMetadata.WTPendingInvite,
				},
			},
		},
	}

	_, resp, err := jm.apiV1Client.SystemusersApi.SystemusersPut(authCtx, userID, contentType, accept, updateReq)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to update user %s, statusCode %d", userID, resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	return nil
}

// GetUserDataByID requests user data from JumpCloud via ID.
func (jm *JumpCloudManager) GetUserDataByID(userID string, _ AppMetadata) (*UserData, error) {
	authCtx := context.WithValue(context.Background(), v1.ContextAPIKey, v1.APIKey{
		Key: jm.apiToken,
	})

	user, resp, err := jm.apiV1Client.SystemusersApi.SystemusersGet(authCtx, userID, contentType, accept, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", userID, resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	return parseV1SystemUser(user), nil
}

// GetAccount returns all the users for a given profile.
func (jm *JumpCloudManager) GetAccount(accountID string) ([]*UserData, error) {
	authCtx := context.WithValue(context.Background(), v1.ContextAPIKey, v1.APIKey{
		Key: jm.apiToken,
	})
	searchFilter := map[string]interface{}{
		"searchFilter": map[string]interface{}{
			"filter": []string{accountID},
			"fields": []string{"wtAccountID"},
		},
	}

	usersList, resp, err := jm.apiV1Client.SearchApi.SearchSystemusersPost(authCtx, contentType, accept, searchFilter)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if jm.appMetrics != nil {
			jm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get account %s users, statusCode %d", accountID, resp.StatusCode)
	}

	if jm.appMetrics != nil {
		jm.appMetrics.IDPMetrics().CountGetAccount()
	}

	usersData := make([]*UserData, 0)
	for _, user := range usersList.Results {
		userData := parseV1SystemUser(user)
		usersData = append(usersData, userData)
	}

	return usersData, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (jm *JumpCloudManager) GetAllAccounts() (map[string][]*UserData, error) {
	authCtx := context.WithValue(context.Background(), v1.ContextAPIKey, v1.APIKey{
		Key: jm.apiToken,
	})

	usersList, resp, err := jm.apiV1Client.SearchApi.SearchSystemusersPost(authCtx, contentType, accept, nil)
	if err != nil {
		return nil, err
	}

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
	for _, user := range usersList.Results {
		userData := parseV1SystemUser(user)

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

// CreateUser creates a new user in JumpCloud Idp and sends an invitation.
func (jm *JumpCloudManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (jm *JumpCloudManager) GetUserByEmail(email string) ([]*UserData, error) {
	authCtx := context.WithValue(context.Background(), v1.ContextAPIKey, v1.APIKey{
		Key: jm.apiToken,
	})
	searchFilter := map[string]interface{}{
		"searchFilter": map[string]interface{}{
			"searchTerm": email,
			"fields":     []string{"email"},
		},
	}

	usersList, resp, err := jm.apiV1Client.SearchApi.SearchSystemusersPost(authCtx, contentType, accept, searchFilter)
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
		userData := parseV1SystemUser(user)
		usersData = append(usersData, userData)
	}

	return usersData, nil
}

// parseV1SystemUser parse JumpCloud system user returned from API V1 to UserData.
func parseV1SystemUser(user v1.Systemuserreturn) *UserData {
	names := []string{user.Firstname, user.Middlename, user.Lastname}
	var appMetadata AppMetadata

	for _, attribute := range user.Attributes {
		if jcAttribute, ok := attribute.(map[string]any); ok {
			if jcAttribute["name"] == "wtAccountID" {
				appMetadata.WTAccountID = jcAttribute["value"].(string)
			}

			if jcAttribute["name"] == "wtPendingInvite" {
				if value, ok := jcAttribute["value"].(bool); ok {
					appMetadata.WTPendingInvite = &value
				}
			}
		}
	}

	return &UserData{
		Email:       user.Email,
		Name:        strings.Join(names, " "),
		ID:          user.Id,
		AppMetadata: appMetadata,
	}
}
