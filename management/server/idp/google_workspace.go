package idp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// GoogleWorkspaceManager Google Workspace manager client instance.
type GoogleWorkspaceManager struct {
	usersService *admin.UsersService
	CustomerID   string
	httpClient   ManagerHTTPClient
	credentials  ManagerCredentials
	helper       ManagerHelper
	appMetrics   telemetry.AppMetrics
}

// GoogleWorkspaceClientConfig Google Workspace manager client configurations.
type GoogleWorkspaceClientConfig struct {
	ServiceAccountKey string
	CustomerID        string
}

// GoogleWorkspaceCredentials Google Workspace authentication information.
type GoogleWorkspaceCredentials struct {
	clientConfig GoogleWorkspaceClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	appMetrics   telemetry.AppMetrics
}

func (gc *GoogleWorkspaceCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

// NewGoogleWorkspaceManager creates a new instance of the GoogleWorkspaceManager.
func NewGoogleWorkspaceManager(config GoogleWorkspaceClientConfig, appMetrics telemetry.AppMetrics) (*GoogleWorkspaceManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.CustomerID == "" {
		return nil, fmt.Errorf("google IdP configuration is incomplete, CustomerID is missing")
	}

	credentials := &GoogleWorkspaceCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	// Create a new Admin SDK Directory service client
	adminCredentials, err := getGoogleCredentials(config.ServiceAccountKey)
	if err != nil {
		return nil, err
	}

	service, err := admin.NewService(context.Background(),
		option.WithScopes(admin.AdminDirectoryUserReadonlyScope),
		option.WithCredentials(adminCredentials),
	)
	if err != nil {
		return nil, err
	}

	return &GoogleWorkspaceManager{
		usersService: service.Users,
		CustomerID:   config.CustomerID,
		httpClient:   httpClient,
		credentials:  credentials,
		helper:       helper,
		appMetrics:   appMetrics,
	}, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (gm *GoogleWorkspaceManager) UpdateUserAppMetadata(_ string, _ AppMetadata) error {
	return nil
}

// GetUserDataByID requests user data from Google Workspace via ID.
func (gm *GoogleWorkspaceManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	user, err := gm.usersService.Get(userID).Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	userData := parseGoogleWorkspaceUser(user)
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetAccount returns all the users for a given profile.
func (gm *GoogleWorkspaceManager) GetAccount(accountID string) ([]*UserData, error) {
	users, err := gm.getAllUsers()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetAccount()
	}

	for index, user := range users {
		user.AppMetadata.WTAccountID = accountID
		users[index] = user
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (gm *GoogleWorkspaceManager) GetAllAccounts() (map[string][]*UserData, error) {
	users, err := gm.getAllUsers()
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], users...)

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	return indexedUsers, nil
}

// getAllUsers returns all users in a Google Workspace account filtered by customer ID.
func (gm *GoogleWorkspaceManager) getAllUsers() ([]*UserData, error) {
	users := make([]*UserData, 0)
	pageToken := ""
	for {
		call := gm.usersService.List().Customer(gm.CustomerID).MaxResults(500)
		if pageToken != "" {
			call.PageToken(pageToken)
		}

		resp, err := call.Do()
		if err != nil {
			return nil, err
		}

		for _, user := range resp.Users {
			users = append(users, parseGoogleWorkspaceUser(user))
		}

		pageToken = resp.NextPageToken
		if pageToken == "" {
			break
		}
	}

	return users, nil
}

// CreateUser creates a new user in Google Workspace and sends an invitation.
func (gm *GoogleWorkspaceManager) CreateUser(_, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (gm *GoogleWorkspaceManager) GetUserByEmail(email string) ([]*UserData, error) {
	user, err := gm.usersService.Get(email).Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	users := make([]*UserData, 0)
	users = append(users, parseGoogleWorkspaceUser(user))

	return users, nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (gm *GoogleWorkspaceManager) InviteUserByID(_ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from GoogleWorkspace.
func (gm *GoogleWorkspaceManager) DeleteUser(userID string) error {
	if err := gm.usersService.Delete(userID).Do(); err != nil {
		return err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	return nil
}

// getGoogleCredentials retrieves Google credentials based on the provided serviceAccountKey.
// It decodes the base64-encoded serviceAccountKey and attempts to obtain credentials using it.
// If that fails, it falls back to using the default Google credentials path.
// It returns the retrieved credentials or an error if unsuccessful.
func getGoogleCredentials(serviceAccountKey string) (*google.Credentials, error) {
	log.Debug("retrieving google credentials from the base64 encoded service account key")
	decodeKey, err := base64.StdEncoding.DecodeString(serviceAccountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode service account key: %w", err)
	}

	creds, err := google.CredentialsFromJSON(
		context.Background(),
		decodeKey,
		admin.AdminDirectoryUserReadonlyScope,
	)
	if err == nil {
		// No need to fallback to the default Google credentials path
		return creds, nil
	}

	log.Debugf("failed to retrieve Google credentials from ServiceAccountKey: %v", err)
	log.Debug("falling back to default google credentials location")

	creds, err = google.FindDefaultCredentials(
		context.Background(),
		admin.AdminDirectoryUserReadonlyScope,
	)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

// parseGoogleWorkspaceUser parse google user to UserData.
func parseGoogleWorkspaceUser(user *admin.User) *UserData {
	return &UserData{
		ID:    user.Id,
		Email: user.PrimaryEmail,
		Name:  user.Name.FullName,
	}
}
