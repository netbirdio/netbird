package legoclient

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
)

// buildRFC2136 adapts a credential field map onto Lego's RFC 2136
// provider — used for self-hosted authoritative DNS (BIND, PowerDNS,
// Knot, NSD) reachable via TSIG-secured dynamic update.
//
// Required fields: "nameserver" (host:port), "tsig_algorithm" (e.g.,
// "hmac-sha256"), "tsig_key" (key name), "tsig_secret" (base64 key).
func buildRFC2136(secret map[string]string) (challenge.Provider, error) {
	nameserver, err := requireField(secret, "rfc2136", "nameserver")
	if err != nil {
		return nil, err
	}
	tsigAlgo, err := requireField(secret, "rfc2136", "tsig_algorithm")
	if err != nil {
		return nil, err
	}
	tsigKey, err := requireField(secret, "rfc2136", "tsig_key")
	if err != nil {
		return nil, err
	}
	tsigSecret, err := requireField(secret, "rfc2136", "tsig_secret")
	if err != nil {
		return nil, err
	}
	cfg := rfc2136.NewDefaultConfig()
	cfg.Nameserver = nameserver
	cfg.TSIGAlgorithm = tsigAlgo
	cfg.TSIGKey = tsigKey
	cfg.TSIGSecret = tsigSecret
	return rfc2136.NewDNSProviderConfig(cfg)
}
