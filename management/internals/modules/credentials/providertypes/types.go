// Package providertypes is the closed set of DNS-01 provider type
// identifiers accepted by the netbird credential store and proxy
// adapters. Adding a new provider requires updating this set AND
// adding the matching adapter at proxy/internal/acme/legoclient/.
package providertypes

const (
	Cloudflare   = "cloudflare"
	Route53      = "route53"
	DigitalOcean = "digitalocean"
	RFC2136      = "rfc2136"
)

// All returns the complete set of accepted provider type identifiers.
// Keep in sync with the proxy-side adapter registry.
func All() []string {
	return []string{Cloudflare, Route53, DigitalOcean, RFC2136}
}

// IsValid reports whether name is a recognized DNS-01 provider type.
func IsValid(name string) bool {
	switch name {
	case Cloudflare, Route53, DigitalOcean, RFC2136:
		return true
	default:
		return false
	}
}
