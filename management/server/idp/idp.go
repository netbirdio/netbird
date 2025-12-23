package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	// UnsetAccountID is a special key to map users without an account ID
	UnsetAccountID = "unset"
)

// Manager idp manager interface
type Manager interface {
	UpdateUserAppMetadata(ctx context.Context, userId string, appMetadata AppMetadata) error
	GetUserDataByID(ctx context.Context, userId string, appMetadata AppMetadata) (*UserData, error)
	GetAccount(ctx context.Context, accountId string) ([]*UserData, error)
	GetAllAccounts(ctx context.Context) (map[string][]*UserData, error)
	CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error)
	GetUserByEmail(ctx context.Context, email string) ([]*UserData, error)
	InviteUserByID(ctx context.Context, userID string) error
	DeleteUser(ctx context.Context, userID string) error
}

// ClientConfig defines common client configuration for all IdP manager
type ClientConfig struct {
	Issuer        string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	GrantType     string
}

// ExtraConfig stores IdP specific config that are unique to individual IdPs
type ExtraConfig map[string]string

// Config an idp configuration struct to be loaded from management server's config file
type Config struct {
	ManagerType               string
	ClientConfig              *ClientConfig
	ExtraConfig               ExtraConfig
	Auth0ClientCredentials    *Auth0ClientConfig
	AzureClientCredentials    *AzureClientConfig
	KeycloakClientCredentials *KeycloakClientConfig
	ZitadelClientCredentials  *ZitadelClientConfig
}

// ManagerCredentials interface that authenticates using the credential of each type of idp
type ManagerCredentials interface {
	Authenticate(ctx context.Context) (JWTToken, error)
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
	Password    string      `json:"-"` // Plain password, only set on user creation, excluded from JSON
}

func (u *UserData) MarshalBinary() (data []byte, err error) {
	return json.Marshal(u)
}

func (u *UserData) UnmarshalBinary(data []byte) (err error) {
	return json.Unmarshal(data, &u)
}

func (u *UserData) Marshal() (data string, err error) {
	d, err := json.Marshal(u)
	return string(d), err
}

func (u *UserData) Unmarshal(data []byte) (err error) {
	return json.Unmarshal(data, &u)
}

// AppMetadata user app metadata to associate with a profile
type AppMetadata struct {
	// WTAccountID is a NetBird (previously Wiretrustee) account id to update in the IDP
	// maps to wt_account_id when json.marshal
	WTAccountID     string `json:"wt_account_id,omitempty"`
	WTPendingInvite *bool  `json:"wt_pending_invite,omitempty"`
	WTInvitedBy     string `json:"wt_invited_by_email,omitempty"`
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
func NewManager(ctx context.Context, config Config, appMetrics telemetry.AppMetrics) (Manager, error) {
	if config.ClientConfig != nil {
		config.ClientConfig.Issuer = strings.TrimSuffix(config.ClientConfig.Issuer, "/")
	}

	switch strings.ToLower(config.ManagerType) {
	case "none", "":
		return nil, nil //nolint:nilnil
	case "auth0":
		auth0ClientConfig := config.Auth0ClientCredentials
		if config.ClientConfig != nil {
			auth0ClientConfig = &Auth0ClientConfig{
				Audience:     config.ExtraConfig["Audience"],
				AuthIssuer:   config.ClientConfig.Issuer,
				ClientID:     config.ClientConfig.ClientID,
				ClientSecret: config.ClientConfig.ClientSecret,
				GrantType:    config.ClientConfig.GrantType,
			}
		}

		return NewAuth0Manager(*auth0ClientConfig, appMetrics)
	case "azure":
		azureClientConfig := config.AzureClientCredentials
		if config.ClientConfig != nil {
			azureClientConfig = &AzureClientConfig{
				ClientID:         config.ClientConfig.ClientID,
				ClientSecret:     config.ClientConfig.ClientSecret,
				GrantType:        config.ClientConfig.GrantType,
				TokenEndpoint:    config.ClientConfig.TokenEndpoint,
				ObjectID:         config.ExtraConfig["ObjectId"],
				GraphAPIEndpoint: config.ExtraConfig["GraphApiEndpoint"],
			}
		}

		return NewAzureManager(*azureClientConfig, appMetrics)
	case "keycloak":
		keycloakClientConfig := config.KeycloakClientCredentials
		if config.ClientConfig != nil {
			keycloakClientConfig = &KeycloakClientConfig{
				ClientID:      config.ClientConfig.ClientID,
				ClientSecret:  config.ClientConfig.ClientSecret,
				GrantType:     config.ClientConfig.GrantType,
				TokenEndpoint: config.ClientConfig.TokenEndpoint,
				AdminEndpoint: config.ExtraConfig["AdminEndpoint"],
			}
		}

		return NewKeycloakManager(*keycloakClientConfig, appMetrics)
	case "zitadel":
		zitadelClientConfig := config.ZitadelClientCredentials
		if config.ClientConfig != nil {
			zitadelClientConfig = &ZitadelClientConfig{
				ClientID:           config.ClientConfig.ClientID,
				ClientSecret:       config.ClientConfig.ClientSecret,
				GrantType:          config.ClientConfig.GrantType,
				TokenEndpoint:      config.ClientConfig.TokenEndpoint,
				ManagementEndpoint: config.ExtraConfig["ManagementEndpoint"],
				PAT:                config.ExtraConfig["PAT"],
			}
		}

		return NewZitadelManager(*zitadelClientConfig, appMetrics)
	case "authentik":
		return NewAuthentikManager(AuthentikClientConfig{
			Issuer:        config.ClientConfig.Issuer,
			ClientID:      config.ClientConfig.ClientID,
			TokenEndpoint: config.ClientConfig.TokenEndpoint,
			GrantType:     config.ClientConfig.GrantType,
			Username:      config.ExtraConfig["Username"],
			Password:      config.ExtraConfig["Password"],
		}, appMetrics)
	case "okta":
		return NewOktaManager(OktaClientConfig{
			Issuer:        config.ClientConfig.Issuer,
			TokenEndpoint: config.ClientConfig.TokenEndpoint,
			GrantType:     config.ClientConfig.GrantType,
			APIToken:      config.ExtraConfig["ApiToken"],
		}, appMetrics)
	case "google":
		return NewGoogleWorkspaceManager(ctx, GoogleWorkspaceClientConfig{
			ServiceAccountKey: config.ExtraConfig["ServiceAccountKey"],
			CustomerID:        config.ExtraConfig["CustomerId"],
		}, appMetrics)
	case "jumpcloud":
		return NewJumpCloudManager(JumpCloudClientConfig{
			APIToken: config.ExtraConfig["ApiToken"],
		}, appMetrics)
	case "pocketid":
		return NewPocketIdManager(PocketIdClientConfig{
			APIToken:           config.ExtraConfig["ApiToken"],
			ManagementEndpoint: config.ExtraConfig["ManagementEndpoint"],
		}, appMetrics)
	case "dex":
		return NewDexManager(DexClientConfig{
			GRPCAddr: config.ExtraConfig["GRPCAddr"],
			Issuer:   config.ClientConfig.Issuer,
		}, appMetrics)
	default:
		return nil, fmt.Errorf("invalid manager type: %s", config.ManagerType)
	}
}
