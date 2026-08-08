package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
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
// with the other PUT endpoints: the request carries every field, replacing the
// mutable ones. The identity fields ride along as a required echo of the
// assigned values — compared, never written — so the endpoint and proxy
// address survive every accepted update.
func TestSettingsHandler_PutReplacesMutableFields(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings",
		`{"proxy_address": "eu.proxy.netbird.io", "enable_prompt_collection": true, "redact_pii": true, "access_log_retention_days": 14}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())

	var before api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &before))

	rec = f.do(t, http.MethodPut, "/agent-network/settings", fmt.Sprintf(
		`{"endpoint": %q, "proxy_address": %q, "enable_log_collection": true, "enable_prompt_collection": false, "redact_pii": false, "access_log_retention_days": 7}`,
		before.Endpoint, before.ProxyAddress))
	require.Equal(t, http.StatusOK, rec.Code, "update PUT must succeed: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.True(t, got.EnableLogCollection, "sent toggle must apply")
	assert.False(t, got.EnablePromptCollection, "sent toggle must apply")
	assert.False(t, got.RedactPii, "sent toggle must apply")
	require.NotNil(t, got.AccessLogRetentionDays)
	assert.Equal(t, 7, *got.AccessLogRetentionDays, "sent retention must apply")
	assert.Equal(t, before.Endpoint, got.Endpoint, "endpoint must survive updates untouched")
	assert.Equal(t, before.ProxyAddress, got.ProxyAddress, "proxy address must survive updates untouched")
}

// TestSettingsHandler_PutRejectsChangedIdentity pins the immutability contract:
// the PUT carries the identity fields like every other field, but they are an
// echo — a request carrying a different endpoint or proxy address is rejected
// as a validation error and the row is left untouched. The comparison is
// lenient about casing (the stored values are normalized lowercase), so a
// client replaying a GET response with different casing is not rejected.
func TestSettingsHandler_PutRejectsChangedIdentity(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings",
		`{"proxy_address": "eu.proxy.netbird.io", "enable_prompt_collection": true}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())
	var before api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &before))

	for name, body := range map[string]string{
		"changed endpoint": fmt.Sprintf(
			`{"endpoint": "other.gateway.example.com", "proxy_address": %q, "enable_log_collection": false, "enable_prompt_collection": false, "redact_pii": false, "access_log_retention_days": 30}`,
			before.ProxyAddress),
		"changed proxy_address": fmt.Sprintf(
			`{"endpoint": %q, "proxy_address": "us.proxy.netbird.io", "enable_log_collection": false, "enable_prompt_collection": false, "redact_pii": false, "access_log_retention_days": 30}`,
			before.Endpoint),
		"omitted identity": `{"enable_log_collection": false, "enable_prompt_collection": false, "redact_pii": false, "access_log_retention_days": 30}`,
	} {
		rec = f.do(t, http.MethodPut, "/agent-network/settings", body)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
			"%s must be rejected: got %d body=%s", name, rec.Code, rec.Body.String())
	}

	// The rejected updates must not have applied anything — toggles included.
	rec = f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, before.Endpoint, got.Endpoint, "rejected PUT must not change the endpoint")
	assert.Equal(t, before.ProxyAddress, got.ProxyAddress, "rejected PUT must not change the proxy address")
	assert.True(t, got.EnablePromptCollection, "rejected PUT must not apply its toggles")

	// An uppercased echo of the assigned values still names the same host and
	// must be accepted.
	rec = f.do(t, http.MethodPut, "/agent-network/settings", fmt.Sprintf(
		`{"endpoint": %q, "proxy_address": %q, "enable_log_collection": true, "enable_prompt_collection": true, "redact_pii": false, "access_log_retention_days": 30}`,
		strings.ToUpper(before.Endpoint), strings.ToUpper(before.ProxyAddress)))
	assert.Equal(t, http.StatusOK, rec.Code,
		"an uppercased identity echo must be accepted: got %d body=%s", rec.Code, rec.Body.String())
}

// TestSettingsHandler_PutOmittedRetentionLandsAsZero documents a residual the
// required-ness of access_log_retention_days does not remove. Marking the field
// required changes the generated client type from *int to int, so a generated
// client cannot omit it — but nothing validates OpenAPI required-ness at
// runtime, so a hand-rolled body without the field still decodes as 0, which
// the API documents as "keep indefinitely".
//
// That is the same latitude the three booleans already have, so it is left
// consistent rather than special-cased. This test exists to make the gap
// explicit: if request validation is ever added, this expectation is what
// changes.
func TestSettingsHandler_PutOmittedRetentionLandsAsZero(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings",
		`{"proxy_address": "eu.proxy.netbird.io", "access_log_retention_days": 14}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())
	var before api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &before))

	rec = f.do(t, http.MethodPut, "/agent-network/settings", fmt.Sprintf(
		`{"endpoint": %q, "proxy_address": %q, "enable_log_collection": true, "enable_prompt_collection": false, "redact_pii": false}`,
		before.Endpoint, before.ProxyAddress))
	require.Equal(t, http.StatusOK, rec.Code, "update PUT must succeed: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.NotNil(t, got.AccessLogRetentionDays)
	assert.Equal(t, 0, *got.AccessLogRetentionDays,
		"a non-conforming body that omits retention still replaces it with the zero value")
}

// TestSettingsHandler_DeleteBeforeBootstrapIs404 pins that DELETE on an
// account with no settings row is a 404, mirroring the PUT.
func TestSettingsHandler_DeleteBeforeBootstrapIs404(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodDelete, "/agent-network/settings", "")
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"DELETE on an unbootstrapped account must 404: got %d body=%s", rec.Code, rec.Body.String())
}

// TestSettingsHandler_DeleteBlockedByProviders pins the first delete guard:
// while any provider exists for the account, the delete is refused with 412
// and the row survives. Providers route through the endpoint — the guard
// keeps DELETE a bootstrap-repair operation rather than a way to abandon a
// configured gateway.
func TestSettingsHandler_DeleteBlockedByProviders(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings", `{"proxy_address": "eu.proxy.netbird.io"}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())
	var before api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &before))

	f.seedProvider(t, "prov-guard")

	rec = f.do(t, http.MethodDelete, "/agent-network/settings", "")
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code,
		"delete with a provider present must be refused: got %d body=%s", rec.Code, rec.Body.String())

	rec = f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, before.Endpoint, got.Endpoint, "the refused delete must leave the row intact")
}

// TestSettingsHandler_DeleteBlockedByActiveProxy pins the second delete
// guard: while a proxy is actively serving the endpoint — an active proxy
// row declaring the endpoint hostname as its cluster address, the dedicated
// shape — the delete is refused with 412. A proxy that has disconnected no
// longer blocks: the guard is about a live serving path, not history.
func TestSettingsHandler_DeleteBlockedByActiveProxy(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	const endpoint = "gw.dedicated.example.com"
	rec := f.do(t, http.MethodPost, "/agent-network/settings", fmt.Sprintf(`{"endpoint": %q}`, endpoint))
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())

	now := time.Now()
	accountID := testAccountID
	proxyRow := &rpproxy.Proxy{
		ID:             "proxy-guard",
		SessionID:      "sess-1",
		ClusterAddress: endpoint,
		AccountID:      &accountID,
		LastSeen:       now,
		ConnectedAt:    &now,
		Status:         rpproxy.StatusConnected,
	}
	require.NoError(t, f.store.SaveProxy(context.Background(), proxyRow))

	rec = f.do(t, http.MethodDelete, "/agent-network/settings", "")
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code,
		"delete with an active proxy at the endpoint must be refused: got %d body=%s", rec.Code, rec.Body.String())

	// Once the proxy disconnects it no longer serves the endpoint, so the
	// delete goes through.
	require.NoError(t, f.store.DisconnectProxy(context.Background(), proxyRow.ID, proxyRow.SessionID))
	rec = f.do(t, http.MethodDelete, "/agent-network/settings", "")
	assert.Equal(t, http.StatusOK, rec.Code,
		"delete after the proxy disconnected must succeed: got %d body=%s", rec.Code, rec.Body.String())
}

// TestSettingsHandler_DeleteReleasesEndpointForFreshBootstrap pins the
// full-reset semantic that gives replace-on-change clients (e.g. Terraform's
// RequiresReplace) a real path: with both guards clear the delete succeeds,
// the account reads as the defaults again, and a fresh bootstrap allocates a
// new endpoint rather than resurrecting the released one.
func TestSettingsHandler_DeleteReleasesEndpointForFreshBootstrap(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/settings",
		`{"proxy_address": "eu.proxy.netbird.io", "enable_prompt_collection": true}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap POST must succeed: %s", rec.Body.String())
	var first api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &first))

	rec = f.do(t, http.MethodDelete, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code,
		"delete with both guards clear must succeed: got %d body=%s", rec.Code, rec.Body.String())

	rec = f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var after api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &after))
	assert.Empty(t, after.Endpoint, "a deleted account must read as unbootstrapped defaults")
	assert.False(t, after.EnablePromptCollection, "the deleted row's toggles must not linger")

	rec = f.do(t, http.MethodPost, "/agent-network/settings", `{"proxy_address": "eu.proxy.netbird.io"}`)
	require.Equal(t, http.StatusOK, rec.Code, "re-bootstrap after delete must succeed: %s", rec.Body.String())
	var second api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &second))
	require.NotEmpty(t, second.Endpoint)
	assert.NotEqual(t, first.Endpoint, second.Endpoint,
		"re-creating allocates a new endpoint; the released hostname is not reserved")
}
