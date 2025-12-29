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

// Manager idp manager interface
// Note: NetBird is the single source of truth for authorization data (roles, account membership, invite status).
// The IdP only stores identity information (email, name, credentials).
type Manager interface {
	// CreateUser creates a new user in the IdP. Returns basic user data (ID, email, name).
	CreateUser(ctx context.Context, email, name string) (*UserData, error)
	// GetUserDataByID retrieves user identity data from the IdP by user ID.
	GetUserDataByID(ctx context.Context, userId string) (*UserData, error)
	// GetUserByEmail searches for users by email address.
	GetUserByEmail(ctx context.Context, email string) ([]*UserData, error)
	// GetAllUsers returns all users from the IdP for cache warming.
	GetAllUsers(ctx context.Context) ([]*UserData, error)
	// InviteUserByID resends an invitation to a user who hasn't completed signup.
	InviteUserByID(ctx context.Context, userID string) error
	// DeleteUser removes a user from the IdP.
	DeleteUser(ctx context.Context, userID string) error
}

// ClientConfig defines common client configuration for the IdP manager
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
	ManagerType              string
	ClientConfig             *ClientConfig
	ExtraConfig              ExtraConfig
	ZitadelClientCredentials *ZitadelClientConfig
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

// UserData represents identity information from the IdP.
// Note: Authorization data (account membership, roles, invite status) is stored in NetBird's DB.
type UserData struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	ID    string `json:"user_id"`
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

// JWTToken a JWT object that holds information of a token
type JWTToken struct {
	AccessToken   string `json:"access_token"`
	ExpiresIn     int    `json:"expires_in"`
	expiresInTime time.Time
	Scope         string `json:"scope"`
	TokenType     string `json:"token_type"`
}

// NewManager returns a new idp manager based on the configuration that it receives.
// Only Zitadel is supported as the IdP manager.
func NewManager(ctx context.Context, config Config, appMetrics telemetry.AppMetrics) (Manager, error) {
	if config.ClientConfig != nil {
		config.ClientConfig.Issuer = strings.TrimSuffix(config.ClientConfig.Issuer, "/")
	}

	switch strings.ToLower(config.ManagerType) {
	case "none", "":
		return nil, nil //nolint:nilnil
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
	default:
		return nil, fmt.Errorf("unsupported IdP manager type: %s (only 'zitadel' is supported)", config.ManagerType)
	}
}
