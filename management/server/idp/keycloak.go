package idp

import "github.com/netbirdio/netbird/management/server/telemetry"

// KeycloakManager keycloak manager client instance.
type KeycloakManager struct {
	authIssuer  string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// KeycloakClientConfig keycloak manager client configurations.
type KeycloakClientConfig struct {
	Audience     string
	AuthIssuer   string
	ClientID     string
	ClientSecret string
	GrantType    string
}

// NewKeycloakManager creates a new instance of the KeycloakManager.
func NewKeycloakManager(config KeycloakClientConfig, appMetrics telemetry.AppMetrics) (*KeycloakManager, error) {
	return &KeycloakManager{}, nil
}

// CreateUser creates a new user in Auth0 Idp and sends an invite.
func (km *KeycloakManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (km *KeycloakManager) GetUserByEmail(email string) ([]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetUserDataByID requests user data from auth0 via ID.
func (km *KeycloakManager) GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map.
func (km *KeycloakManager) GetAccount(accountId string) ([]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (km *KeycloakManager) GetAllAccounts() (map[string][]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map.
func (km *KeycloakManager) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {
	panic("not implemented") // TODO: Implement
}
