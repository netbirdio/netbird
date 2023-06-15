package idp

import (
	"fmt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"net/http"
	"time"
)

// JumpCloudManager jumpcloud manager client instance.
type JumpCloudManager struct {
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// JumpCloudClientConfig jumpcloud manager client configurations.
type JumpCloudClientConfig struct {
	Issuer        string
	TokenEndpoint string
	GrantType     string
}

// JumpCloudCredentials jumpcloud authentication information.
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

	if config.Issuer == "" {
		return nil, fmt.Errorf("jumpcloud IdP configuration is incomplete, Issuer is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("jumpcloud IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("jumpcloud IdP configuration is incomplete, GrantType is missing")
	}

	credentials := &JumpCloudCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &JumpCloudManager{
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// Authenticate retrieves access token to use the jumpcloud user API.
func (jc *JumpCloudCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (jm *JumpCloudManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	//TODO implement me
	panic("implement me")
}

// GetUserDataByID requests user data from jumpcloud via ID.
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
func (j *JumpCloudManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// CreateUser creates a new user in jumpcloud Idp and sends an invitation.
func (jm *JumpCloudManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (jm *JumpCloudManager) GetUserByEmail(email string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}
