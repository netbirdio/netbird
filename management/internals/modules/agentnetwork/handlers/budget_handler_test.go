package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestBudgetRuleHandler_RoundTrip seeds a budget rule via the store and asserts
// the GET wire shape carries targets and the reused PolicyLimits cap shape. The
// create/update/delete success paths go through accountManager.StoreEvent which
// this fixture doesn't wire — they are covered by the manager-level no-mock
// test (TestAgentNetwork_BudgetRuleCRUD_RealManager).
func TestBudgetRuleHandler_RoundTrip(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rule := &agentNetworkTypes.AccountBudgetRule{
		ID:           "ainbud_test",
		AccountID:    testAccountID,
		Name:         "org-monthly",
		Enabled:      true,
		TargetGroups: []string{"grp-eng"},
		TargetUsers:  []string{"user-alice"},
		Limits: agentNetworkTypes.PolicyLimits{
			TokenLimit:  agentNetworkTypes.PolicyTokenLimit{Enabled: true, GroupCap: 100000, UserCap: 10000, WindowSeconds: 2_592_000},
			BudgetLimit: agentNetworkTypes.PolicyBudgetLimit{Enabled: true, GroupCapUsd: 500, WindowSeconds: 2_592_000},
		},
	}
	require.NoError(t, f.store.SaveAgentNetworkBudgetRule(context.Background(), rule))

	rec := f.do(t, http.MethodGet, "/agent-network/budget-rules/"+rule.ID, "")
	require.Equal(t, http.StatusOK, rec.Code, "GET must succeed: %s", rec.Body.String())

	var got api.AgentNetworkBudgetRule
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "org-monthly", got.Name, "name must round-trip")
	assert.Equal(t, []string{"grp-eng"}, got.TargetGroups, "target groups must round-trip")
	assert.Equal(t, []string{"user-alice"}, got.TargetUsers, "target users must round-trip")
	assert.Equal(t, int64(100000), got.Limits.TokenLimit.GroupCap, "token group cap must round-trip")
	assert.Equal(t, int64(2_592_000), got.Limits.BudgetLimit.WindowSeconds, "budget window must round-trip")
}

// TestBudgetRuleHandler_ListReturnsArray asserts the list endpoint returns a
// JSON array (never null) for an account with no rules.
func TestBudgetRuleHandler_ListReturnsArray(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodGet, "/agent-network/budget-rules", "")
	require.Equal(t, http.StatusOK, rec.Code, "GET must succeed: %s", rec.Body.String())
	assert.Equal(t, "[]", trimSpace(rec.Body.String()), "empty account must return an empty array, not null")
}

// TestBudgetRuleHandler_RejectsMissingName covers the validation path (which
// runs before the manager call, so it works without a wired accountManager).
func TestBudgetRuleHandler_RejectsMissingName(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	body := `{
        "name": "",
        "limits": {
            "token_limit": {"enabled": false, "group_cap": 0, "user_cap": 0, "window_seconds": 0},
            "budget_limit": {"enabled": false, "group_cap_usd": 0, "user_cap_usd": 0, "window_seconds": 0}
        }
    }`
	rec := f.do(t, http.MethodPost, "/agent-network/budget-rules", body)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
		"missing name must be rejected as a validation error (not a route/auth 4xx): got %d body=%s", rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "name",
		"rejection body must name the offending field, proving the validation path: %s", rec.Body.String())
}

// TestBudgetRuleHandler_RejectsSubMinuteWindow proves budget rules reuse the
// policy-limit validation (enabled limit needs window >= 60s).
func TestBudgetRuleHandler_RejectsSubMinuteWindow(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	body := `{
        "name": "bad-window",
        "limits": {
            "token_limit": {"enabled": true, "group_cap": 1000, "user_cap": 0, "window_seconds": 30},
            "budget_limit": {"enabled": false, "group_cap_usd": 0, "user_cap_usd": 0, "window_seconds": 0}
        }
    }`
	rec := f.do(t, http.MethodPost, "/agent-network/budget-rules", body)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
		"sub-minute window must be rejected as a validation error (not a route/auth 4xx): got %d body=%s", rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "window_seconds",
		"rejection body must name the offending window_seconds field, proving the validation path: %s", rec.Body.String())
}

// TestSettingsHandler_GetExposesCollectionToggles asserts the GET settings wire
// shape carries the account-level collection toggles after a store seed.
func TestSettingsHandler_GetExposesCollectionToggles(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	require.NoError(t, f.store.SaveAgentNetworkSettings(context.Background(), &agentNetworkTypes.Settings{
		AccountID:              testAccountID,
		Cluster:                "eu.proxy.netbird.io",
		Subdomain:              "violet",
		EnableLogCollection:    true,
		EnablePromptCollection: true,
		RedactPii:              false,
	}))

	rec := f.do(t, http.MethodGet, "/agent-network/settings", "")
	require.Equal(t, http.StatusOK, rec.Code, "GET must succeed: %s", rec.Body.String())

	var got api.AgentNetworkSettings
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.True(t, got.EnableLogCollection, "log collection toggle must surface on the wire")
	assert.True(t, got.EnablePromptCollection, "prompt collection toggle must surface on the wire")
	assert.False(t, got.RedactPii, "redact toggle must surface its false value")
	assert.Equal(t, "violet.eu.proxy.netbird.io", got.Endpoint, "endpoint stays computed from immutable cluster+subdomain")
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == '\n' || s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	return s
}
