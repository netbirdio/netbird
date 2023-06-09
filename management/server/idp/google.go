package idp

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"net/http"
	"os"
	"sync"
	"time"
)

// GoogleManager google manager client instance.
type GoogleManager struct {
	usersService *admin.UsersService
	Domain       string
	httpClient   ManagerHTTPClient
	credentials  ManagerCredentials
	helper       ManagerHelper
	appMetrics   telemetry.AppMetrics
}

// GoogleClientConfig google manager client configurations.
type GoogleClientConfig struct {
	ServiceAccountKeyPath string
	Domain                string
}

// GoogleCredentials google authentication information.
type GoogleCredentials struct {
	clientConfig GoogleClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

func (gc *GoogleCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

// NewGoogleManager creates a new instance of the GoogleManager.
func NewGoogleManager(config GoogleClientConfig, appMetrics telemetry.AppMetrics) (*GoogleManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.ServiceAccountKeyPath == "" {
		return nil, fmt.Errorf("google IdP configuration is incomplete, ServiceAccountKeyPath is missing")
	}

	if config.Domain == "" {
		return nil, fmt.Errorf("google IdP configuration is incomplete, Domain is missing")
	}

	credentials := &GoogleCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	// Create a new Admin SDK Directory service client
	adminServiceClient, err := getClient(config.ServiceAccountKeyPath)
	if err != nil {
		return nil, err
	}

	service, err := admin.NewService(context.Background(), option.WithHTTPClient(adminServiceClient))
	if err != nil {
		return nil, err
	}

	return &GoogleManager{
		usersService: service.Users,
		Domain:       config.Domain,
		httpClient:   httpClient,
		credentials:  credentials,
		helper:       helper,
		appMetrics:   appMetrics,
	}, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (gm *GoogleManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	user, err := gm.usersService.Get(userID).Do()
	if err != nil {
		return err
	}

	metadata, err := gm.helper.Marshal(appMetadata)
	if err != nil {
		return err
	}

	user.CustomSchemas = map[string]googleapi.RawMessage{
		"app_metadata": metadata,
	}

	_, err = gm.usersService.Update(userID, user).Do()
	if err != nil {
		return err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	return nil
}

// GetUserDataByID requests user data from keycloak via ID.
func (gm *GoogleManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	user, err := gm.usersService.Get(userID).Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	return parseGoogleUser(user)
}

// GetAccount returns all the users for a given profile.
func (gm *GoogleManager) GetAccount(accountID string) ([]*UserData, error) {
	query := fmt.Sprintf("app_metadata.wt_account_id=\"%s\"", accountID)
	usersList, err := gm.usersService.List().Domain(gm.Domain).Query(query).Do()
	if err != nil {
		return nil, err
	}

	usersData := make([]*UserData, 0)
	for _, user := range usersList.Users {
		userData, err := parseGoogleUser(user)
		if err != nil {
			return nil, err
		}

		usersData = append(usersData, userData)
	}

	return usersData, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (gm *GoogleManager) GetAllAccounts() (map[string][]*UserData, error) {
	usersList, err := gm.usersService.List().Domain(gm.Domain).Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	indexedUsers := make(map[string][]*UserData)
	for _, user := range usersList.Users {
		userData, err := parseGoogleUser(user)
		if err != nil {
			return nil, err
		}

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

// CreateUser creates a new user in Google Workspace and sends an invitation.
func (gm *GoogleManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (gm *GoogleManager) GetUserByEmail(email string) ([]*UserData, error) {
	user, err := gm.usersService.Get(email).Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	userData, err := parseGoogleUser(user)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	users = append(users, userData)

	return users, nil
}

// getClient creates a new HTTP client with the service account credentials
func getClient(keyPath string) (*http.Client, error) {
	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read service account key file: %v", err)
	}

	// Include a scope that grants the ability to view and manage user provisioning
	// within your domain
	config, err := google.JWTConfigFromJSON(keyFile, admin.AdminDirectoryUserScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse service account key file: %v", err)
	}

	return config.Client(context.Background()), nil
}

// parseGoogleUser parse google user to UserData.
func parseGoogleUser(user *admin.User) (*UserData, error) {
	var (
		emailAddress string
		appMetadata  AppMetadata
	)

	// Get user primary emailAddress
	if user.Emails != nil {
		emailsList, ok := user.Emails.([]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to get emails")
		}

		for _, emailData := range emailsList {
			email, ok := emailData.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("failed to get email data")
			}

			isPrimary, ok := email["primary"].(bool)
			if ok && isPrimary {
				emailAddress = email["address"].(string)
				break
			}
		}
	}

	// Get app metadata from custom schemas
	if user.CustomSchemas != nil {
		rawMessage := user.CustomSchemas["app_metadata"]
		helper := JsonParser{}

		if err := helper.Unmarshal(rawMessage, &appMetadata); err != nil {
			return nil, err
		}
	}

	return &UserData{
		ID:          user.Id,
		Email:       emailAddress,
		Name:        user.Name.FullName,
		AppMetadata: appMetadata,
	}, nil
}
