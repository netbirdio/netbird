package legoclient

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"

	"github.com/netbirdio/netbird/management/internals/modules/credentials/secretpayload"
)

// buildCloudflare adapts a credential field map onto Lego's Cloudflare
// DNS-01 provider. Required field: "auth_token" (a scoped Cloudflare
// API token with Zone:DNS:Edit on the target zone).
//
// Legacy credentials stored Cloudflare tokens as plain strings; the
// fallback (secretpayload.LegacyKey) accepts those without a migration.
func buildCloudflare(secret map[string]string) (challenge.Provider, error) {
	token := secret["auth_token"]
	if token == "" {
		token = secret[secretpayload.LegacyKey]
	}
	if token == "" {
		return nil, requireFieldErr("cloudflare", "auth_token")
	}
	cfg := cloudflare.NewDefaultConfig()
	cfg.AuthToken = token
	return cloudflare.NewDNSProviderConfig(cfg)
}

// requireFieldErr is used by buildCloudflare for the legacy-fallback
// path (where requireField wouldn't apply because it accepts either
// of two keys).
func requireFieldErr(providerName, key string) error {
	_, err := requireField(map[string]string{}, providerName, key)
	return err
}
