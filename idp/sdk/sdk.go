// Package sdk provides an embeddable SDK for the Dex OIDC identity provider.
package sdk

import (
	"context"

	"github.com/dexidp/dex/storage"

	"github.com/netbirdio/netbird/idp/dex"
)

// DexIdP wraps the Dex provider with a builder pattern
type DexIdP struct {
	provider *dex.Provider
	config   *dex.Config
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

// Start initializes and starts the embedded OIDC provider
func (d *DexIdP) Start(ctx context.Context) error {
	provider, err := dex.NewProvider(ctx, d.config)
	if err != nil {
		return err
	}
	d.provider = provider
	return provider.Start(ctx)
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

// IssuerURL returns the OIDC issuer URL
func (d *DexIdP) IssuerURL() string {
	return d.config.Issuer
}

// DiscoveryEndpoint returns the OIDC discovery endpoint URL
func (d *DexIdP) DiscoveryEndpoint() string {
	return d.config.Issuer + "/dex/.well-known/openid-configuration"
}
