package legoclient

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
)

// ProviderBuilder constructs a Lego DNS-01 challenge provider from a
// decoded credential field map. Each builder validates its required
// keys and maps them onto the Lego provider's Config struct.
type ProviderBuilder func(secret map[string]string) (challenge.Provider, error)

// providerRegistry maps DNS-01 provider type identifiers to their
// adapter functions. Adding a new provider is one line here plus the
// matching build* function in a sibling file.
//
// Keep in sync with management/internals/modules/credentials/providertypes
// (source of truth for accepted provider type strings).
var providerRegistry = map[string]ProviderBuilder{
	"cloudflare":   buildCloudflare,
	"route53":      buildRoute53,
	"digitalocean": buildDigitalOcean,
	"rfc2136":      buildRFC2136,
}

// BuildProvider returns a configured Lego DNS-01 provider for the
// named type. Returns a clear error if the name is unknown.
func BuildProvider(name string, secret map[string]string) (challenge.Provider, error) {
	builder, ok := providerRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q", name)
	}
	return builder(secret)
}

// requireField returns the value for key from secret, or an error
// indicating which provider is missing which field. Used by adapters
// to keep their own code tight.
func requireField(secret map[string]string, providerName, key string) (string, error) {
	v, ok := secret[key]
	if !ok || v == "" {
		return "", fmt.Errorf("%s credential is missing required field %q", providerName, key)
	}
	return v, nil
}
