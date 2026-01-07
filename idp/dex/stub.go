//go:build !cgo

// Package dex provides an embedded Dex OIDC identity provider.
// This stub exists for non-CGO builds where SQLite is unavailable.
package dex

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
)

var errNoCGO = errors.New("embedded IdP requires CGO (SQLite)")

// Config for simple provider creation
type Config struct {
	Issuer   string
	Port     int
	DataDir  string
	DevMode  bool
	GRPCAddr string
}

// Provider wraps a Dex server
type Provider struct{}

// NewProvider creates a new Provider
func NewProvider(_ context.Context, _ *Config) (*Provider, error) { return nil, errNoCGO }

// NewProviderFromYAML creates a Provider from YAML config
func NewProviderFromYAML(_ context.Context, _ *YAMLConfig) (*Provider, error) { return nil, errNoCGO }

// Start starts the server
func (p *Provider) Start(_ context.Context) error { return errNoCGO }

// Stop stops the server
func (p *Provider) Stop(_ context.Context) error { return errNoCGO }

// EnsureDefaultClients ensures default clients exist
func (p *Provider) EnsureDefaultClients(_ context.Context, _, _ []string) error { return errNoCGO }

// Storage returns the storage
func (p *Provider) Storage() storage.Storage { return nil }

// Handler returns the HTTP handler
func (p *Provider) Handler() http.Handler { return nil }

// CreateUser creates a user
func (p *Provider) CreateUser(_ context.Context, _, _, _ string) (string, error) {
	return "", errNoCGO
}

// GetUser gets a user
func (p *Provider) GetUser(_ context.Context, _ string) (storage.Password, error) {
	return storage.Password{}, errNoCGO
}

// GetUserByID gets a user by ID
func (p *Provider) GetUserByID(_ context.Context, _ string) (storage.Password, error) {
	return storage.Password{}, errNoCGO
}

// DeleteUser deletes a user
func (p *Provider) DeleteUser(_ context.Context, _ string) error { return errNoCGO }

// ListUsers lists users
func (p *Provider) ListUsers(_ context.Context) ([]storage.Password, error) { return nil, errNoCGO }

// GetRedirectURI returns the redirect URI
func (p *Provider) GetRedirectURI() string { return "" }

// GetIssuer returns the issuer
func (p *Provider) GetIssuer() string { return "" }

// GetTokenEndpoint returns the token endpoint
func (p *Provider) GetTokenEndpoint() string { return "" }

// GetDeviceAuthEndpoint returns the device auth endpoint
func (p *Provider) GetDeviceAuthEndpoint() string { return "" }

// GetAuthorizationEndpoint returns the auth endpoint
func (p *Provider) GetAuthorizationEndpoint() string { return "" }

// GetKeysLocation returns the keys location
func (p *Provider) GetKeysLocation() string { return "" }

// ConnectorConfig for identity provider connectors
type ConnectorConfig struct {
	ID, Name, Type, Issuer, ClientID, ClientSecret         string
	Scopes                                                  []string
	UserIDKey, UserNameKey, EmailKey                        string
	InsecureSkipVerify                                      bool
	AuthorizationURL, TokenURL, UserInfoURL                 string
	IdentityProviderType                                    string
}

// CreateConnector creates a connector
func (p *Provider) CreateConnector(_ context.Context, _ *ConnectorConfig) (*ConnectorConfig, error) {
	return nil, errNoCGO
}

// GetConnector gets a connector
func (p *Provider) GetConnector(_ context.Context, _ string) (*ConnectorConfig, error) {
	return nil, errNoCGO
}

// ListConnectors lists connectors
func (p *Provider) ListConnectors(_ context.Context) ([]*ConnectorConfig, error) { return nil, errNoCGO }

// UpdateConnector updates a connector
func (p *Provider) UpdateConnector(_ context.Context, _ *ConnectorConfig) error { return errNoCGO }

// DeleteConnector deletes a connector
func (p *Provider) DeleteConnector(_ context.Context, _ string) error { return errNoCGO }

// EncodeDexUserID encodes a user ID
func EncodeDexUserID(_, _ string) string { return "" }

// DecodeDexUserID decodes a user ID
func DecodeDexUserID(_ string) (string, string, error) { return "", "", errNoCGO }

// YAMLConfig for YAML-based configuration
type YAMLConfig struct {
	Issuer           string           `yaml:"issuer" json:"issuer"`
	Storage          Storage          `yaml:"storage" json:"storage"`
	Web              Web              `yaml:"web" json:"web"`
	GRPC             GRPC             `yaml:"grpc" json:"grpc"`
	OAuth2           OAuth2           `yaml:"oauth2" json:"oauth2"`
	Expiry           Expiry           `yaml:"expiry" json:"expiry"`
	Logger           Logger           `yaml:"logger" json:"logger"`
	Frontend         Frontend         `yaml:"frontend" json:"frontend"`
	StaticConnectors []Connector      `yaml:"connectors" json:"connectors"`
	StaticClients    []storage.Client `yaml:"staticClients" json:"staticClients"`
	EnablePasswordDB bool             `yaml:"enablePasswordDB" json:"enablePasswordDB"`
	StaticPasswords  []Password       `yaml:"staticPasswords" json:"staticPasswords"`
}

// Validate validates config
func (c *YAMLConfig) Validate() error { return errNoCGO }

// ToServerConfig converts to server config
func (c *YAMLConfig) ToServerConfig(_ storage.Storage, _ *slog.Logger) server.Config {
	return server.Config{}
}

// GetRefreshTokenPolicy gets refresh policy
func (c *YAMLConfig) GetRefreshTokenPolicy(_ *slog.Logger) (*server.RefreshTokenPolicy, error) {
	return nil, errNoCGO
}

// LoadConfig loads config from file
func LoadConfig(_ string) (*YAMLConfig, error) { return nil, errNoCGO }

// Web config
type Web struct {
	HTTP, HTTPS    string
	AllowedOrigins []string
	AllowedHeaders []string
}

// GRPC config
type GRPC struct{ Addr, TLSCert, TLSKey, TLSClientCA string }

// OAuth2 config
type OAuth2 struct {
	SkipApprovalScreen, AlwaysShowLoginScreen bool
	PasswordConnector                         string
	ResponseTypes, GrantTypes                 []string
}

// Expiry config
type Expiry struct {
	SigningKeys, IDTokens, AuthRequests, DeviceRequests string
	RefreshTokens                                       RefreshTokensExpiry
}

// RefreshTokensExpiry config
type RefreshTokensExpiry struct {
	ReuseInterval, ValidIfNotUsedFor, AbsoluteLifetime string
	DisableRotation                                    bool
}

// Logger config
type Logger struct{ Level, Format string }

// Frontend config
type Frontend struct {
	Dir, Theme, Issuer, LogoURL string
	Extra                       map[string]string
}

// Storage config
type Storage struct {
	Type   string
	Config map[string]interface{}
}

// OpenStorage opens storage
func (s *Storage) OpenStorage(_ *slog.Logger) (storage.Storage, error) { return nil, errNoCGO }

// Password type
type Password storage.Password

// Connector config
type Connector struct {
	Type, Name, ID string
	Config         map[string]interface{}
}

// ToStorageConnector converts to storage connector
func (c *Connector) ToStorageConnector() (storage.Connector, error) {
	return storage.Connector{}, errNoCGO
}

// StorageConfig interface
type StorageConfig interface {
	Open(logger *slog.Logger) (storage.Storage, error)
}
