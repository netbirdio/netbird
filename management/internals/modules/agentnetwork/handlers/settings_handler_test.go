package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestSettingsHandler_GetUnbootstrappedReturnsDefaults pins the settings-read
// convention shared with the account and DNS settings endpoints: settings
// always read as a JSON object. Before bootstrap that object carries the
// defaults with an empty endpoint/proxy_address (the "not bootstrapped"
// signal) and no timestamps — never a 404 and never the legacy null body.
func TestSettingsHandler_GetUnbootstrappedReturnsDefaults(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code,
		"unbootstrapped account must read as 200 with defaults: got %d body=%s", rec.Code, rec.Body.String())
	require.NotEqual(t, "null", trimSpace(rec.Body.String()),
		"the legacy 200+null shape must not come back")

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Empty(t, got.Endpoint, "endpoint must be empty until bootstrapped")
	assert.Empty(t, got.ProxyAddress, "proxy address must be empty until bootstrapped")
	assert.False(t, got.Dedicated, "an unbootstrapped account has no serving shape")
	assert.True(t, got.EnableLogCollection, "defaults must show log collection on, matching bootstrap")
	assert.False(t, got.EnablePromptCollection, "defaults must show prompt collection off")
	assert.False(t, got.RedactPii, "defaults must show redaction off")
	require.NotNil(t, got.AccessLogRetentionDays)
	assert.Equal(t, 30, *got.AccessLogRetentionDays, "defaults must show the bootstrap retention")
	assert.Nil(t, got.CreatedAt, "no timestamps before a row exists")
	assert.Nil(t, got.UpdatedAt, "no timestamps before a row exists")
}

// TestSettingsHandler_PostBootstrapsLabeled covers the labeled bootstrap
// shape: a POST carrying a proxy_address allocates a label beneath it, so the
// endpoint hangs one label under the shared cluster's address and the pin is
// not dedicated. Toggles riding along apply; omitted ones keep defaults.
func TestSettingsHandler_PostBootstrapsLabeled(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings",
		`{"proxy_address": "eu.proxy.netbird.io", "enable_prompt_collection": true, "access_log_retention_days": 14}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "eu.proxy.netbird.io", got.ProxyAddress, "proxy address must be pinned from the request")
	require.NotEmpty(t, got.Endpoint, "endpoint must be allocated at bootstrap")
	assert.True(t, strings.HasSuffix(got.Endpoint, ".eu.proxy.netbird.io"),
		"labeled endpoint must hang off the proxy address: %s", got.Endpoint)
	label := strings.TrimSuffix(got.Endpoint, ".eu.proxy.netbird.io")
	assert.NotContains(t, label, ".", "the allocated label must be a single DNS label: %s", label)
	assert.False(t, got.Dedicated, "a labeled pin is not dedicated")
	assert.True(t, got.EnableLogCollection, "omitted toggle must keep its default")
	assert.True(t, got.EnablePromptCollection, "toggle from the bootstrap request must apply")
	require.NotNil(t, got.AccessLogRetentionDays)
	assert.Equal(t, 14, *got.AccessLogRetentionDays, "retention from the bootstrap request must apply")
	assert.NotNil(t, got.CreatedAt, "a persisted row carries timestamps")

	// The row is now readable via GET.
	rec = f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code, "GET after bootstrap must succeed")
	var read api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &read))
	assert.Equal(t, got.Endpoint, read.Endpoint, "GET must return the bootstrapped endpoint")
}

// TestSettingsHandler_PostBootstrapsSelfAddressed covers the dedicated shape:
// a POST carrying an endpoint claims the hostname verbatim, the proxy address
// equals it, and the pin reads as dedicated. The claim is legitimate before
// any proxy declares the address (address-first).
func TestSettingsHandler_PostBootstrapsSelfAddressed(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings",
		`{"endpoint": "Brave-Otter.Gateway.Example.com"}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "brave-otter.gateway.example.com", got.Endpoint,
		"endpoint must be claimed verbatim, lowercased")
	assert.Equal(t, got.Endpoint, got.ProxyAddress, "self-addressed: the proxy address is the endpoint")
	assert.True(t, got.Dedicated, "a self-addressed pin is dedicated")
	assert.True(t, got.EnableLogCollection, "omitted toggles must keep their defaults")
}

// TestSettingsHandler_PostRequiresExactlyOneIdentityField pins the request
// contract: proxy_address and endpoint are mutually exclusive and one is
// required — both or neither is a validation error, not a guess.
func TestSettingsHandler_PostRequiresExactlyOneIdentityField(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings", `{}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
		"empty POST must be rejected: got %d body=%s", rec.Code, rec.Body.String())

	rec = f.do(t, http.MethodPost, "/agent-network/settings",
		`{"proxy_address": "eu.proxy.netbird.io", "endpoint": "brave-otter.gateway.example.com"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
		"POST with both identity fields must be rejected: got %d body=%s", rec.Code, rec.Body.String())
}

// TestSettingsHandler_PostRejectsMalformedHostnames pins per-write input
// validation: shapes canonicalization cannot repair — trailing dots, embedded
// whitespace, empty labels — are rejected with a validation error instead of
// landing in an immutable column.
func TestSettingsHandler_PostRejectsMalformedHostnames(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	for name, body := range map[string]string{
		"trailing dot":     `{"endpoint": "gateway.example.com."}`,
		"leading dot":      `{"endpoint": ".gateway.example.com"}`,
		"inner whitespace": `{"endpoint": "gate way.example.com"}`,
		"empty label":      `{"proxy_address": "eu..proxy.netbird.io"}`,
	} {
		rec := f.do(t, http.MethodPost, "/agent-network/settings", body)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
			"%s must be rejected: got %d body=%s", name, rec.Code, rec.Body.String())
	}
}

// TestSettingsHandler_PostConflictsOnSecondBootstrap pins that bootstrap is a
// one-time create: a second POST returns 409 and leaves the row untouched.
func TestSettingsHandler_PostConflictsOnSecondBootstrap(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings", `{"proxy_address": "eu.proxy.netbird.io"}`)
	require.Equal(t, http.StatusOK, rec.Code, "first bootstrap must succeed: %s", rec.Body.String())
	var first api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &first))

	rec = f.do(t, http.MethodPost, "/agent-network/settings", `{"proxy_address": "us.proxy.netbird.io"}`)
	assert.Equal(t, http.StatusConflict, rec.Code,
		"second bootstrap must 409: got %d body=%s", rec.Code, rec.Body.String())

	rec = f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, first.Endpoint, got.Endpoint, "the original endpoint must survive the rejected bootstrap")
	assert.Equal(t, first.ProxyAddress, got.ProxyAddress, "the original proxy address must survive")
}

// TestSettingsHandler_PutBeforeBootstrapIs404 pins that a PUT cannot conjure a
// settings row out of nothing — bootstrap is the explicit POST — and the
// error points the caller there.
func TestSettingsHandler_PutBeforeBootstrapIs404(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPut, "/agent-network/settings",
		`{"enable_log_collection": false, "enable_prompt_collection": false, "redact_pii": false}`)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"PUT on an unbootstrapped account must 404: got %d body=%s", rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "/api/agent-network/settings",
		"the error must point the caller at the bootstrap POST: %s", rec.Body.String())
}

// TestSettingsHandler_PutReplacesMutableFields pins the update contract shared
// with the other PUT endpoints: the request replaces every mutable field, so a
// toggle absent from the JSON lands as its zero value rather than being
// preserved. The identity fields are not part of the PUT schema at all, so
// the endpoint and proxy address survive updates by construction.
func TestSettingsHandler_PutReplacesMutableFields(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings",
		`{"proxy_address": "eu.proxy.netbird.io", "enable_prompt_collection": true, "redact_pii": true, "access_log_retention_days": 14}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())

	var before api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &before))

	rec = f.do(t, http.MethodPut, "/agent-network/settings",
		`{"enable_log_collection": true, "enable_prompt_collection": false, "redact_pii": false}`)
	require.Equal(t, http.StatusOK, rec.Code, "update PUT must succeed: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.True(t, got.EnableLogCollection, "sent toggle must apply")
	assert.False(t, got.EnablePromptCollection, "sent toggle must apply")
	assert.False(t, got.RedactPii, "sent toggle must apply")
	require.NotNil(t, got.AccessLogRetentionDays)
	assert.Equal(t, 0, *got.AccessLogRetentionDays,
		"retention absent from the request must land as the zero value — PUT replaces all mutable fields")
	assert.Equal(t, before.Endpoint, got.Endpoint, "endpoint must survive updates untouched")
	assert.Equal(t, before.ProxyAddress, got.ProxyAddress, "proxy address must survive updates untouched")
}
