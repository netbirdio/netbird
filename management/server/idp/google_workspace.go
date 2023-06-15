package idp

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"net/http"
	"strings"
	"time"
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
		option.WithScopes(admin.AdminDirectoryUserScope, admin.AdminDirectoryUserschemaScope),
		option.WithCredentials(adminCredentials),
	)
	if err != nil {
		return nil, err
	}

	if err = configureAppMetadataSchema(service, config.CustomerID); err != nil {
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
func (gm *GoogleWorkspaceManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	metadata, err := gm.helper.Marshal(appMetadata)
	if err != nil {
		return err
	}

	user := &admin.User{
		CustomSchemas: map[string]googleapi.RawMessage{
			"app_metadata": metadata,
		},
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

// GetUserDataByID requests user data from Google Workspace via ID.
func (gm *GoogleWorkspaceManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	user, err := gm.usersService.Get(userID).Projection("full").Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	return parseGoogleWorkspaceUser(user)
}

// GetAccount returns all the users for a given profile.
func (gm *GoogleWorkspaceManager) GetAccount(accountID string) ([]*UserData, error) {
	query := fmt.Sprintf("app_metadata.wt_account_id=\"%s\"", accountID)
	usersList, err := gm.usersService.List().Customer(gm.CustomerID).Query(query).Projection("full").Do()
	if err != nil {
		return nil, err
	}

	usersData := make([]*UserData, 0)
	for _, user := range usersList.Users {
		userData, err := parseGoogleWorkspaceUser(user)
		if err != nil {
			return nil, err
		}

		usersData = append(usersData, userData)
	}

	return usersData, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (gm *GoogleWorkspaceManager) GetAllAccounts() (map[string][]*UserData, error) {
	usersList, err := gm.usersService.List().Customer(gm.CustomerID).Projection("full").Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	indexedUsers := make(map[string][]*UserData)
	for _, user := range usersList.Users {
		userData, err := parseGoogleWorkspaceUser(user)
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
func (gm *GoogleWorkspaceManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	invite := true
	metadata := AppMetadata{
		WTAccountID:     accountID,
		WTPendingInvite: &invite,
	}

	username := &admin.UserName{}
	fields := strings.Fields(name)
	if n := len(fields); n > 0 {
		username.GivenName = strings.Join(fields[:n-1], " ")
		username.FamilyName = fields[n-1]
	}

	payload, err := gm.helper.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	user := &admin.User{
		Name:         username,
		PrimaryEmail: email,
		CustomSchemas: map[string]googleapi.RawMessage{
			"app_metadata": payload,
		},
		Password: GeneratePassword(8, 1, 1, 1),
	}
	user, err = gm.usersService.Insert(user).Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountCreateUser()
	}

	return parseGoogleWorkspaceUser(user)
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (gm *GoogleWorkspaceManager) GetUserByEmail(email string) ([]*UserData, error) {
	user, err := gm.usersService.Get(email).Projection("full").Do()
	if err != nil {
		return nil, err
	}

	if gm.appMetrics != nil {
		gm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	userData, err := parseGoogleWorkspaceUser(user)
	if err != nil {
		return nil, err
	}

	users := make([]*UserData, 0)
	users = append(users, userData)

	return users, nil
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
		admin.AdminDirectoryUserschemaScope,
		admin.AdminDirectoryUserScope,
	)
	if err == nil {
		return creds, err
	}

	log.Debugf("failed to retrieve Google credentials from ServiceAccountKey: %v", err)
	log.Debug("falling back to default google credentials location")

	creds, err = google.FindDefaultCredentials(
		context.Background(),
		admin.AdminDirectoryUserschemaScope,
		admin.AdminDirectoryUserScope,
	)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

// configureAppMetadataSchema create a custom schema for managing app metadata fields in Google Workspace.
func configureAppMetadataSchema(service *admin.Service, customerID string) error {
	schemaList, err := service.Schemas.List(customerID).Do()
	if err != nil {
		return err
	}

	// checks if app_metadata schema is already created
	for _, schema := range schemaList.Schemas {
		if schema.SchemaName == "app_metadata" {
			return nil
		}
	}

	// create new app_metadata schema
	appMetadataSchema := &admin.Schema{
		SchemaName: "app_metadata",
		Fields: []*admin.SchemaFieldSpec{
			{
				FieldName:   "wt_account_id",
				FieldType:   "STRING",
				MultiValued: false,
			},
			{
				FieldName:   "wt_pending_invite",
				FieldType:   "BOOL",
				MultiValued: false,
			},
		},
	}
	_, err = service.Schemas.Insert(customerID, appMetadataSchema).Do()
	if err != nil {
		return err
	}

	return nil
}

// parseGoogleWorkspaceUser parse google user to UserData.
func parseGoogleWorkspaceUser(user *admin.User) (*UserData, error) {
	var appMetadata AppMetadata

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
		Email:       user.PrimaryEmail,
		Name:        user.Name.FullName,
		AppMetadata: appMetadata,
	}, nil
}
