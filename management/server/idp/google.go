package idp

import (
	"fmt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"net/http"
	"sync"
	"time"
)

// GoogleManager google manager client instance.
type GoogleManager struct {
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
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

	return &GoogleManager{
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
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

func (gm *GoogleManager) GetAccount(gccountID string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) CreateUser(email string, name string, gccountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (gm *GoogleManager) GetUserByEmail(email string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}
