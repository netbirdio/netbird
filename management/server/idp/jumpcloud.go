package idp

import (
	"fmt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"net/http"
	"time"
)

// JumpcloudManager jumpcloud manager client instance.
type JumpcloudManager struct {
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// JumpcloudClientConfig jumpcloud manager client configurations.
type JumpcloudClientConfig struct {
	Issuer        string
	TokenEndpoint string
	GrantType     string
}

// JumpcloudCredentials jumpcloud authentication information.
type JumpcloudCredentials struct {
	clientConfig JumpcloudClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	appMetrics   telemetry.AppMetrics
}

// NewJumpcloudManager creates a new instance of the JumpcloudManager.
func NewJumpcloudManager(config JumpcloudClientConfig, appMetrics telemetry.AppMetrics) (*JumpcloudManager, error) {
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

	credentials := &JumpcloudCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &JumpcloudManager{
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// Authenticate retrieves access token to use the jumpcloud user API.
func (jc *JumpcloudCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (j *JumpcloudManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	//TODO implement me
	panic("implement me")
}

// GetUserDataByID requests user data from jumpcloud via ID.
func (j *JumpcloudManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetAccount returns all the users for a given profile.
func (j *JumpcloudManager) GetAccount(accountID string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (j *JumpcloudManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// CreateUser creates a new user in jumpcloud Idp and sends an invitation.
func (j *JumpcloudManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	//TODO implement me
	panic("implement me")
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (j *JumpcloudManager) GetUserByEmail(email string) ([]*UserData, error) {
	//TODO implement me
	panic("implement me")
}
