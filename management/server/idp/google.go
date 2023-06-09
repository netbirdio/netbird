package idp

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
	"net/http"
	"os"
	"sync"
	"time"
)

// GoogleManager google manager client instance.
type GoogleManager struct {
	usersService *admin.UsersService
	httpClient   ManagerHTTPClient
	credentials  ManagerCredentials
	helper       ManagerHelper
	appMetrics   telemetry.AppMetrics
}

// GoogleClientConfig google manager client configurations.
type GoogleClientConfig struct {
	ServiceAccountKeyPath string
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
		httpClient:   httpClient,
		credentials:  credentials,
		helper:       helper,
		appMetrics:   appMetrics,
	}, nil
}

func (gm *GoogleManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetAccount(accountID string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetUserByEmail(email string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
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
