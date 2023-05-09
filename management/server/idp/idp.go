package idp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// Manager idp manager interface
type Manager interface {
	UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error
	GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error)
	GetAccount(accountId string) ([]*UserData, error)
	GetAllAccounts() (map[string][]*UserData, error)
	CreateUser(email string, name string, accountID string) (*UserData, error)
	GetUserByEmail(email string) ([]*UserData, error)
}

// OIDCConfig specifies configuration for OpenID Connect provider
// These configurations are automatically loaded from the OIDC endpoint
type OIDCConfig struct {
	Issuer        string
	TokenEndpoint string
}

// Config an idp configuration struct to be loaded from management server's config file
type Config struct {
	ManagerType               string
	OIDCConfig                OIDCConfig `json:"-"`
	Auth0ClientCredentials    Auth0ClientConfig
	AzureClientCredentials    AzureClientConfig
	KeycloakClientCredentials KeycloakClientConfig
	ZitadelClientCredentials  ZitadelClientConfig
}

// ManagerCredentials interface that authenticates using the credential of each type of idp
type ManagerCredentials interface {
	Authenticate() (JWTToken, error)
}

// ManagerHTTPClient http client interface for API calls
type ManagerHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ManagerHelper helper
type ManagerHelper interface {
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
}

type UserData struct {
	Email       string      `json:"email"`
	Name        string      `json:"name"`
	ID          string      `json:"user_id"`
	AppMetadata AppMetadata `json:"app_metadata"`
}

// AppMetadata user app metadata to associate with a profile
type AppMetadata struct {
	// WTAccountID is a NetBird (previously Wiretrustee) account id to update in the IDP
	// maps to wt_account_id when json.marshal
	WTAccountID     string `json:"wt_account_id,omitempty"`
	WTPendingInvite *bool  `json:"wt_pending_invite"`
}

// JWTToken a JWT object that holds information of a token
type JWTToken struct {
	AccessToken   string `json:"access_token"`
	ExpiresIn     int    `json:"expires_in"`
	expiresInTime time.Time
	Scope         string `json:"scope"`
	TokenType     string `json:"token_type"`
}

// NewManager returns a new idp manager based on the configuration that it receives
func NewManager(config Config, appMetrics telemetry.AppMetrics) (Manager, error) {
	switch strings.ToLower(config.ManagerType) {
	case "none", "":
		return nil, nil
	case "auth0":
		return NewAuth0Manager(config.Auth0ClientCredentials, appMetrics)
	case "azure":
		return NewAzureManager(config.AzureClientCredentials, appMetrics)
	case "keycloak":
		return NewKeycloakManager(config.KeycloakClientCredentials, appMetrics)
	case "zitadel":
		config.ZitadelClientCredentials.TokenEndpoint = config.OIDCConfig.TokenEndpoint
		config.ZitadelClientCredentials.GrantType = "client_credentials"
		return NewZitadelManager(config.ZitadelClientCredentials, appMetrics)
	default:
		return nil, fmt.Errorf("invalid manager type: %s", config.ManagerType)
	}
}
