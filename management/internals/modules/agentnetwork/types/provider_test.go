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

// TestProvider_MetadataDisabled_RoundTrip covers the request→provider→response
// mapping of metadata_disabled, with the same update semantics: nil preserves,
// explicit false clears.
func TestProvider_MetadataDisabled_RoundTrip(t *testing.T) {
	enable := true
	disable := false

	base := func() *api.AgentNetworkProviderRequest {
		return &api.AgentNetworkProviderRequest{
			ProviderId:  "bedrock_api",
			Name:        "bedrock",
			UpstreamUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
		}
	}

	p := NewProvider("acc-1")

	req := base()
	req.MetadataDisabled = &enable
	p.FromAPIRequest(req)
	assert.True(t, p.MetadataDisabled, "create with metadata_disabled=true must set the field")
	assert.True(t, p.ToAPIResponse().MetadataDisabled, "response must surface metadata_disabled")

	// Omitting the field on update leaves the stored value untouched.
	p.FromAPIRequest(base())
	assert.True(t, p.MetadataDisabled, "omitting metadata_disabled on update must preserve it")

	// Explicit false clears it (re-enables metadata).
	req = base()
	req.MetadataDisabled = &disable
	p.FromAPIRequest(req)
	assert.False(t, p.MetadataDisabled, "explicit false must clear metadata_disabled")
	assert.False(t, p.ToAPIResponse().MetadataDisabled, "response must reflect the cleared value")
}

// TestProvider_IdentityHeaders_AlwaysOnWire pins that the identity header
// fields are always present in the API response — an explicitly cleared
// ("") header must round-trip as "" rather than vanish, so API consumers
// (e.g. the Terraform provider) never observe a value other than the one
// they wrote.
func TestProvider_IdentityHeaders_AlwaysOnWire(t *testing.T) {
	set := "x-bf-dim-netbird_user_id"
	empty := ""

	base := func() *api.AgentNetworkProviderRequest {
		return &api.AgentNetworkProviderRequest{
			ProviderId:  "custom",
			Name:        "bifrost",
			UpstreamUrl: "https://bifrost.internal",
		}
	}

	p := NewProvider("acc-1")
	resp := p.ToAPIResponse()
	assert.Equal(t, "", resp.IdentityHeaderUserId, "unset header must surface as empty string, not be omitted")
	assert.Equal(t, "", resp.IdentityHeaderGroups, "unset header must surface as empty string, not be omitted")

	req := base()
	req.IdentityHeaderUserId = &set
	p.FromAPIRequest(req)
	assert.Equal(t, set, p.ToAPIResponse().IdentityHeaderUserId, "configured header must round-trip")

	// Omitting the field preserves it.
	p.FromAPIRequest(base())
	assert.Equal(t, set, p.ToAPIResponse().IdentityHeaderUserId, "omitted header must preserve the stored value")

	// An explicit "" clears it AND stays visible on the wire.
	req = base()
	req.IdentityHeaderUserId = &empty
	p.FromAPIRequest(req)
	assert.Equal(t, "", p.ToAPIResponse().IdentityHeaderUserId, "cleared header must round-trip as empty string")
}
