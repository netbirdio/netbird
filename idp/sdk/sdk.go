// Package sdk provides an embeddable SDK for the Dex OIDC identity provider.
package sdk

import (
	"context"

	"github.com/dexidp/dex/storage"

	"github.com/netbirdio/netbird/idp/dex"
)

// DexIdP wraps the Dex provider with a builder pattern
type DexIdP struct {
	provider   *dex.Provider
	config     *dex.Config
	yamlConfig *dex.YAMLConfig
}

// Option configures a DexIdP instance
type Option func(*dex.Config)

// WithIssuer sets the OIDC issuer URL
func WithIssuer(issuer string) Option {
	return func(c *dex.Config) { c.Issuer = issuer }
}

// WithPort sets the HTTP port
func WithPort(port int) Option {
	return func(c *dex.Config) { c.Port = port }
}

// WithDataDir sets the data directory for storage
func WithDataDir(dir string) Option {
	return func(c *dex.Config) { c.DataDir = dir }
}

// WithDevMode enables development mode (allows HTTP)
func WithDevMode(dev bool) Option {
	return func(c *dex.Config) { c.DevMode = dev }
}

// WithGRPCAddr sets the gRPC API address
func WithGRPCAddr(addr string) Option {
	return func(c *dex.Config) { c.GRPCAddr = addr }
}

// New creates a new DexIdP instance with the given options
func New(opts ...Option) (*DexIdP, error) {
	config := &dex.Config{
		Port:    33081,
		DevMode: true,
	}

	for _, opt := range opts {
		opt(config)
	}

	return &DexIdP{config: config}, nil
}

// NewFromConfigFile creates a new DexIdP instance from a YAML config file
func NewFromConfigFile(path string) (*DexIdP, error) {
	yamlConfig, err := dex.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return &DexIdP{yamlConfig: yamlConfig}, nil
}

// NewFromYAMLConfig creates a new DexIdP instance from a YAMLConfig
func NewFromYAMLConfig(yamlConfig *dex.YAMLConfig) (*DexIdP, error) {
	return &DexIdP{yamlConfig: yamlConfig}, nil
}

// Start initializes and starts the embedded OIDC provider
func (d *DexIdP) Start(ctx context.Context) error {
	var err error
	if d.yamlConfig != nil {
		d.provider, err = dex.NewProviderFromYAML(ctx, d.yamlConfig)
	} else {
		d.provider, err = dex.NewProvider(ctx, d.config)
	}
	if err != nil {
		return err
	}
	return d.provider.Start(ctx)
}

// Stop gracefully shuts down the provider
func (d *DexIdP) Stop(ctx context.Context) error {
	if d.provider != nil {
		return d.provider.Stop(ctx)
	}
	return nil
}

// EnsureDefaultClients creates the default NetBird OAuth clients
func (d *DexIdP) EnsureDefaultClients(ctx context.Context, dashboardURIs, cliURIs []string) error {
	return d.provider.EnsureDefaultClients(ctx, dashboardURIs, cliURIs)
}

// Storage exposes Dex storage for direct user/client/connector management
// Use storage.Client, storage.Password, storage.Connector directly
func (d *DexIdP) Storage() storage.Storage {
	return d.provider.Storage()
}

// CreateUser creates a new user with the given email, username, and password.
// Returns the encoded user ID in Dex's format.
func (d *DexIdP) CreateUser(ctx context.Context, email, username, password string) (string, error) {
	return d.provider.CreateUser(ctx, email, username, password)
}

// DeleteUser removes a user by email
func (d *DexIdP) DeleteUser(ctx context.Context, email string) error {
	return d.provider.DeleteUser(ctx, email)
}

// ListUsers returns all users
func (d *DexIdP) ListUsers(ctx context.Context) ([]storage.Password, error) {
	return d.provider.ListUsers(ctx)
}

// IssuerURL returns the OIDC issuer URL
func (d *DexIdP) IssuerURL() string {
	if d.yamlConfig != nil {
		return d.yamlConfig.Issuer
	}
	return d.config.Issuer
}

// DiscoveryEndpoint returns the OIDC discovery endpoint URL
func (d *DexIdP) DiscoveryEndpoint() string {
	return d.IssuerURL() + "/.well-known/openid-configuration"
}
