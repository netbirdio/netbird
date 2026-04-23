package idp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

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

func (gc *GoogleWorkspaceCredentials) Authenticate(_ context.Context) (JWTToken, error) {
	return JWTToken{}, nil
}

// NewGoogleWorkspaceManager creates a new instance of the GoogleWorkspaceManager.
func NewGoogleWorkspaceManager(ctx context.Context, config GoogleWorkspaceClientConfig, appMetrics telemetry.AppMetrics) (*GoogleWorkspaceManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   idpTimeout(),
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
	credentialsOption, err := getGoogleCredentialsOption(ctx, config.ServiceAccountKey)
	if err != nil {
		return nil, err
	}

	service, err := admin.NewService(context.Background(),
		option.WithScopes(admin.AdminDirectoryUserReadonlyScope),
		credentialsOption,
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
func (gm *GoogleWorkspaceManager) UpdateUserAppMetadata(_ context.Context, _ string, _ AppMetadata) error {
	return nil
}

// GetUserDataByID requests user data from Google Workspace via ID.
func (gm *GoogleWorkspaceManager) GetUserDataByID(_ context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
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
func (gm *GoogleWorkspaceManager) GetAccount(_ context.Context, accountID string) ([]*UserData, error) {
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
func (gm *GoogleWorkspaceManager) GetAllAccounts(_ context.Context) (map[string][]*UserData, error) {
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
func (gm *GoogleWorkspaceManager) CreateUser(_ context.Context, _, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (gm *GoogleWorkspaceManager) GetUserByEmail(_ context.Context, email string) ([]*UserData, error) {
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
func (gm *GoogleWorkspaceManager) InviteUserByID(_ context.Context, _ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from GoogleWorkspace.
func (gm *GoogleWorkspaceManager) DeleteUser(_ context.Context, userID string) error {
	if err := gm.usersService.Delete(userID).Do(); err != nil {
		return err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	return nil
}

// getGoogleCredentialsOption returns the google.golang.org/api option carrying
// Google credentials derived from the provided serviceAccountKey.
// It decodes the base64-encoded serviceAccountKey and uses it as the credentials JSON.
// If the key is empty, it falls back to the default Google credentials path.
func getGoogleCredentialsOption(ctx context.Context, serviceAccountKey string) (option.ClientOption, error) {
	log.WithContext(ctx).Debug("retrieving google credentials from the base64 encoded service account key")
	decodeKey, err := base64.StdEncoding.DecodeString(serviceAccountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode service account key: %w", err)
	}

	if len(decodeKey) > 0 {
		return option.WithAuthCredentialsJSON(option.ServiceAccount, decodeKey), nil
	}

	log.WithContext(ctx).Debug("no service account key provided, falling back to default google credentials location")

	creds, err := google.FindDefaultCredentials(
		ctx,
		admin.AdminDirectoryUserReadonlyScope,
	)
	if err != nil {
		return nil, err
	}

	return option.WithCredentials(creds), nil
}

// parseGoogleWorkspaceUser parse google user to UserData.
func parseGoogleWorkspaceUser(user *admin.User) *UserData {
	return &UserData{
		ID:    user.Id,
		Email: user.PrimaryEmail,
		Name:  user.Name.FullName,
	}
}
