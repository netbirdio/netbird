package legoclient

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
)

// buildDigitalOcean adapts a credential field map onto Lego's
// DigitalOcean provider. Required field: "auth_token" (a personal
// access token with at least write scope).
func buildDigitalOcean(secret map[string]string) (challenge.Provider, error) {
	token, err := requireField(secret, "digitalocean", "auth_token")
	if err != nil {
		return nil, err
	}
	cfg := digitalocean.NewDefaultConfig()
	cfg.AuthToken = token
	return digitalocean.NewDNSProviderConfig(cfg)
}
