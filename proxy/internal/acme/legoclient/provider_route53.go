package legoclient

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// buildRoute53 adapts a credential field map onto Lego's Route 53
// provider.
//
// Required fields: "access_key_id", "secret_access_key".
// Optional fields: "region" (defaults to AWS region resolution),
// "hosted_zone_id" (forces a specific zone), "session_token" (for
// temporary STS credentials).
func buildRoute53(secret map[string]string) (challenge.Provider, error) {
	accessKey, err := requireField(secret, "route53", "access_key_id")
	if err != nil {
		return nil, err
	}
	secretKey, err := requireField(secret, "route53", "secret_access_key")
	if err != nil {
		return nil, err
	}
	cfg := route53.NewDefaultConfig()
	cfg.AccessKeyID = accessKey
	cfg.SecretAccessKey = secretKey
	if v := secret["region"]; v != "" {
		cfg.Region = v
	}
	if v := secret["hosted_zone_id"]; v != "" {
		cfg.HostedZoneID = v
	}
	if v := secret["session_token"]; v != "" {
		cfg.SessionToken = v
	}
	return route53.NewDNSProviderConfig(cfg)
}
