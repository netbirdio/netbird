package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestSettingsHandler_GetUnbootstrappedReturnsDefaults pins the settings-read
// convention shared with the account and DNS settings endpoints: settings
// always read as a JSON object. Before bootstrap that object carries the
// defaults with an empty cluster/subdomain/endpoint (the "not bootstrapped"
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
	assert.Empty(t, got.Cluster, "cluster must be empty until bootstrapped")
	assert.Empty(t, got.Subdomain, "subdomain must be empty until bootstrapped")
	assert.Empty(t, got.Endpoint, "endpoint must be empty until bootstrapped, not a bare dot")
	assert.True(t, got.EnableLogCollection, "defaults must show log collection on, matching bootstrap")
	assert.False(t, got.EnablePromptCollection, "defaults must show prompt collection off")
	assert.False(t, got.RedactPii, "defaults must show redaction off")
	require.NotNil(t, got.AccessLogRetentionDays)
	assert.Equal(t, 30, *got.AccessLogRetentionDays, "defaults must show the bootstrap retention")
	assert.Nil(t, got.CreatedAt, "no timestamps before a row exists")
	assert.Nil(t, got.UpdatedAt, "no timestamps before a row exists")
}

// TestSettingsHandler_PutBootstrapsWithCluster covers the settings-first
// bootstrap path: a PUT carrying a cluster on an unbootstrapped account
// creates the row (cluster pinned, subdomain assigned) and applies the
// mutable fields from the same request.
func TestSettingsHandler_PutBootstrapsWithCluster(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPut, "/agent-network/settings",
		`{"cluster": "eu.proxy.netbird.io", "enable_log_collection": true, "enable_prompt_collection": true, "redact_pii": false, "access_log_retention_days": 30}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap PUT must succeed: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "eu.proxy.netbird.io", got.Cluster, "cluster must be pinned from the request")
	assert.NotEmpty(t, got.Subdomain, "subdomain must be assigned at bootstrap")
	assert.Equal(t, got.Subdomain+".eu.proxy.netbird.io", got.Endpoint, "endpoint must combine subdomain and cluster")
	assert.True(t, got.EnableLogCollection, "toggle from the bootstrap request must apply")
	assert.True(t, got.EnablePromptCollection, "toggle from the bootstrap request must apply")
	require.NotNil(t, got.AccessLogRetentionDays)
	assert.Equal(t, 30, *got.AccessLogRetentionDays, "retention from the bootstrap request must apply")

	// The row is now readable via GET.
	rec = f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code, "GET after bootstrap must succeed")
}

// TestSettingsHandler_PutWithoutClusterOnUnbootstrapped pins that a PUT
// without a cluster cannot conjure a settings row out of nothing — there is
// no cluster to pin — and surfaces as 404 like the GET.
func TestSettingsHandler_PutWithoutClusterOnUnbootstrapped(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPut, "/agent-network/settings",
		`{"enable_log_collection": false, "enable_prompt_collection": false, "redact_pii": false}`)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cluster-less PUT on an unbootstrapped account must 404: got %d body=%s", rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "cluster",
		"the error must point the caller at the bootstrap paths: %s", rec.Body.String())
}

// TestSettingsHandler_PutReplacesMutableFields pins the update contract shared
// with the other PUT endpoints: the request replaces every mutable field, so a
// toggle absent from the JSON lands as its zero value rather than being
// preserved. Cluster and subdomain survive untouched.
func TestSettingsHandler_PutReplacesMutableFields(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPut, "/agent-network/settings",
		`{"cluster": "eu.proxy.netbird.io", "enable_log_collection": true, "enable_prompt_collection": true, "redact_pii": true, "access_log_retention_days": 14}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap PUT must succeed: %s", rec.Body.String())

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
	assert.Equal(t, before.Cluster, got.Cluster, "cluster must survive updates untouched")
	assert.Equal(t, before.Subdomain, got.Subdomain, "subdomain must survive updates untouched")
}

// TestSettingsHandler_PutRejectsClusterChange pins cluster immutability: once
// assigned, a differing cluster is rejected as a validation error instead of
// being silently ignored, so callers never observe a value other than the one
// they sent. Echoing the assigned cluster back stays valid, which lets
// declarative clients send their full desired state idempotently.
func TestSettingsHandler_PutRejectsClusterChange(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPut, "/agent-network/settings",
		`{"cluster": "eu.proxy.netbird.io", "enable_log_collection": true, "enable_prompt_collection": false, "redact_pii": false}`)
	require.Equal(t, http.StatusOK, rec.Code, "bootstrap PUT must succeed: %s", rec.Body.String())

	rec = f.do(t, http.MethodPut, "/agent-network/settings",
		`{"cluster": "us.proxy.netbird.io", "enable_log_collection": true, "enable_prompt_collection": false, "redact_pii": false}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
		"cluster change must be rejected as a validation error: got %d body=%s", rec.Code, rec.Body.String())

	rec = f.do(t, http.MethodPut, "/agent-network/settings",
		`{"cluster": "eu.proxy.netbird.io", "enable_log_collection": true, "enable_prompt_collection": false, "redact_pii": true}`)
	require.Equal(t, http.StatusOK, rec.Code, "echoing the assigned cluster must stay valid: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "eu.proxy.netbird.io", got.Cluster, "cluster must be unchanged")
	assert.True(t, got.RedactPii, "toggle sent alongside the echoed cluster must apply")
}
