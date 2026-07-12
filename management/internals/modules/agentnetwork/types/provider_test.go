package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestProvider_SkipTLSVerification_RoundTrip covers the request→provider→
// response mapping of skip_tls_verification, including the update semantics
// (nil pointer preserves, explicit false clears).
func TestProvider_SkipTLSVerification_RoundTrip(t *testing.T) {
	enable := true
	disable := false

	base := func() *api.AgentNetworkProviderRequest {
		return &api.AgentNetworkProviderRequest{
			ProviderId:  "openai_api",
			Name:        "internal",
			UpstreamUrl: "https://gw.internal",
		}
	}

	p := NewProvider("acc-1")

	req := base()
	req.SkipTlsVerification = &enable
	p.FromAPIRequest(req)
	assert.True(t, p.SkipTLSVerification, "create with skip_tls_verification=true must set the field")
	assert.True(t, p.ToAPIResponse().SkipTlsVerification, "response must surface skip_tls_verification")

	// Omitting the field on update leaves the stored value untouched.
	p.FromAPIRequest(base())
	assert.True(t, p.SkipTLSVerification, "omitting skip_tls_verification on update must preserve it")

	// Explicit false clears it.
	req = base()
	req.SkipTlsVerification = &disable
	p.FromAPIRequest(req)
	assert.False(t, p.SkipTLSVerification, "explicit false must clear skip_tls_verification")
	assert.False(t, p.ToAPIResponse().SkipTlsVerification, "response must reflect the cleared value")
}
