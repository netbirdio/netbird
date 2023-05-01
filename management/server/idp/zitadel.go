package idp

import (
	"sync"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// ZitadelManager zitadel manager client instance.
type ZitadelManager struct {
	AuthIssuer  string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// ZitadelClientConfig zitadel manager client configurations.
type ZitadelClientConfig struct {
	AuthIssuer   string
	ClientID     string
	ClientSecret string
	GrantType    string
}

// ZitadelCredentials zitadel authentication information.
type ZitadelCredentials struct {
	clientConfig ZitadelClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewZitadelManager creates a new instance of the ZitadelManager.
func NewZitadelManager(config ZitadelClientConfig, appMetrics telemetry.AppMetrics) (*ZitadelManager, error) {
	return &ZitadelManager{}, nil
}

// Authenticate retrieves access token to use the Zitadel Management API.
func (zc *ZitadelCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

// CreateUser creates a new user in zitadel Idp and sends an invite.
func (zm *ZitadelManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	return nil, nil
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (zm *ZitadelManager) GetUserByEmail(email string) ([]*UserData, error) {
	return nil, nil
}

// GetUserDataByID requests user data from keycloak via ID.
func (zm *ZitadelManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	return nil, nil
}

// GetAccount returns all the users for a given profile.
func (zm *ZitadelManager) GetAccount(accountID string) ([]*UserData, error) {
	return nil, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (zm *ZitadelManager) GetAllAccounts() (map[string][]*UserData, error) {
	return nil, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (zm *ZitadelManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	return nil
}
