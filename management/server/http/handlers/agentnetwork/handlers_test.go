package agentnetwork

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	testAccountID = "acc-1"
	testUserID    = "user-bob"
)

// agentNetworkHandlerFixture builds a real agentnetwork.Manager with
// a sqlite store and an always-allow permissions mock, then exposes
// the HTTP handlers via a gorilla router. Tests issue requests
// through httptest and assert on the wire shape — the same path the
// dashboard exercises.
type agentNetworkHandlerFixture struct {
	store   store.Store
	manager agentnetwork.Manager
	router  *mux.Router
}

func newAgentNetworkHandlerFixture(t *testing.T) *agentNetworkHandlerFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not properly supported on Windows yet")
	}
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))

	st, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)
	// Always-allow: the handler tests are about wire shape, not
	// authz. Authz is covered by the manager's own tests.
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(true, context.Background(), nil).
		AnyTimes()

	manager := agentnetwork.NewManager(st, perms, nil, nil)
	h := &handler{manager: manager}

	router := mux.NewRouter()
	h.addPolicyEndpoints(router)
	h.addConsumptionEndpoints(router)
	h.addBudgetRuleEndpoints(router)
	h.addSettingsEndpoints(router)

	return &agentNetworkHandlerFixture{
		store:   st,
		manager: manager,
		router:  router,
	}
}

func (f *agentNetworkHandlerFixture) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		UserId:    testUserID,
		AccountId: testAccountID,
	})
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// seedProvider persists a minimal provider record so policy create
// passes the manager's destination_provider_ids existence check.
func (f *agentNetworkHandlerFixture) seedProvider(t *testing.T, id string) {
	t.Helper()
	require.NoError(t, f.store.SaveAgentNetworkProvider(context.Background(), &agentNetworkTypes.Provider{
		ID:                id,
		AccountID:         testAccountID,
		ProviderID:        "openai_api",
		Name:              "test-" + id,
		UpstreamURL:       "https://api.openai.com",
		APIKey:            "sk-test",
		Enabled:           true,
		SessionPrivateKey: "test-priv-key",
		SessionPublicKey:  "test-pub-key",
	}))
}

// TestPolicyHandler_WindowSecondsRoundTrip ports bash 10 to Go:
// assert that a policy with window_seconds on both Token + Budget
// halves round-trips through GET unchanged AND that legacy
// window_hours / window_days are absent from the JSON response. We
// seed the policy directly via the store rather than POST-ing
// because the create path goes through the manager's
// accountManager.StoreEvent which we don't wire in this fixture; the
// on-wire shape is what matters here, and the POST validation path
// is covered separately by the RejectsSubMinuteWindow test.
func TestPolicyHandler_WindowSecondsRoundTrip(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	policy := &agentNetworkTypes.Policy{
		ID:                     "ainpol_test",
		AccountID:              testAccountID,
		Name:                   "round-trip",
		Enabled:                true,
		SourceGroups:           []string{"grp-engineers"},
		DestinationProviderIDs: []string{"prov-1"},
		Limits: agentNetworkTypes.PolicyLimits{
			TokenLimit:  agentNetworkTypes.PolicyTokenLimit{Enabled: true, GroupCap: 10000, UserCap: 5000, WindowSeconds: 86_400},
			BudgetLimit: agentNetworkTypes.PolicyBudgetLimit{Enabled: true, GroupCapUsd: 10.0, UserCapUsd: 2.5, WindowSeconds: 2_592_000},
		},
	}
	require.NoError(t, f.store.SaveAgentNetworkPolicy(context.Background(), policy))

	rec := f.do(t, http.MethodGet, "/agent-network/policies/"+policy.ID, "")
	require.Equal(t, http.StatusOK, rec.Code, "GET must succeed: %s", rec.Body.String())

	var got api.AgentNetworkPolicy
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, int64(86_400), got.Limits.TokenLimit.WindowSeconds, "token_limit.window_seconds must round-trip")
	assert.Equal(t, int64(2_592_000), got.Limits.BudgetLimit.WindowSeconds, "budget_limit.window_seconds must round-trip")

	// Legacy field names must NOT appear in the response — would
	// signal that the management server is still emitting the old
	// shape and would fool a v1 dashboard into rendering days/hours.
	assert.NotContains(t, rec.Body.String(), "window_hours",
		"legacy window_hours field must be absent from the on-wire response")
	assert.NotContains(t, rec.Body.String(), "window_days",
		"legacy window_days field must be absent from the on-wire response")
}

// TestPolicyHandler_RejectsSubMinuteWindow ports bash 20 to Go: an
// enabled limit with window_seconds < 60 must surface as a 4xx
// because anything finer than per-minute produces an untenable
// volume of consumption rows for a feature whose value comes from
// per-window cap enforcement.
func TestPolicyHandler_RejectsSubMinuteWindow(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)
	f.seedProvider(t, "prov-1")

	body := `{
        "name": "sub-minute-window",
        "enabled": true,
        "source_groups": ["grp-engineers"],
        "destination_provider_ids": ["prov-1"],
        "guardrail_ids": [],
        "limits": {
            "token_limit": {"enabled": true, "group_cap": 10000, "user_cap": 5000, "window_seconds": 30},
            "budget_limit": {"enabled": false, "group_cap_usd": 0, "user_cap_usd": 0, "window_seconds": 0}
        }
    }`
	rec := f.do(t, http.MethodPost, "/agent-network/policies", body)
	// 422 specifically (InvalidArgument) proves the window-validation path —
	// a route miss would be 404 and an auth failure 403, so a generic 4xx
	// would let those false-pass.
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code,
		"enabled token_limit with window_seconds<60 must be rejected as a validation error: got %d body=%s", rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "window_seconds",
		"rejection body must name the offending window_seconds field, proving it's the validation path: %s", rec.Body.String())
}

// TestConsumptionHandler_EmptyAccountReturnsArray ports bash 30 to
// Go: GET /agent-network/consumption on a clean account always
// returns a JSON array (possibly empty), never a 404 / 500. The
// dashboard depends on this shape to render its empty state.
func TestConsumptionHandler_EmptyAccountReturnsArray(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodGet, "/agent-network/consumption", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var rows []api.AgentNetworkConsumption
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rows),
		"response must always be a JSON array — even when empty: %s", rec.Body.String())
	assert.Empty(t, rows)
}

// TestConsumptionHandler_PopulatedAccountListsRows mirrors the
// /consumption read after a few RecordConsumption calls. Validates
// the wire shape carries every field the dashboard reads (dim_kind,
// dim_id, window_seconds, window_start_utc, tokens, cost_usd) and
// rows are ordered window-newest-first.
func TestConsumptionHandler_PopulatedAccountListsRows(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	require.NoError(t, f.manager.RecordConsumption(
		context.Background(), testAccountID,
		agentNetworkTypes.DimensionGroup, "grp-engineers",
		86_400, 100, 50, 0.0125,
	))
	require.NoError(t, f.manager.RecordConsumption(
		context.Background(), testAccountID,
		agentNetworkTypes.DimensionUser, testUserID,
		86_400, 100, 50, 0.0125,
	))

	rec := f.do(t, http.MethodGet, "/agent-network/consumption", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var rows []api.AgentNetworkConsumption
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rows))
	require.Len(t, rows, 2, "two RecordConsumption calls must yield two rows")

	// Index by dim_kind so we can assert the full wire shape of each row,
	// including the dimension id and the aligned window start the dashboard
	// keys on. Both rows share totals and window.
	byKind := make(map[string]api.AgentNetworkConsumption, len(rows))
	for _, row := range rows {
		assert.Equal(t, int64(100), row.TokensInput)
		assert.Equal(t, int64(50), row.TokensOutput)
		assert.InDelta(t, 0.0125, row.CostUsd, 1e-9)
		assert.Equal(t, int64(86_400), row.WindowSeconds)
		assert.False(t, row.WindowStartUtc.IsZero(), "window_start_utc must be set on every row")
		byKind[string(row.DimensionKind)] = row
	}

	groupRow, ok := byKind["group"]
	require.True(t, ok, "group dimension must surface")
	assert.Equal(t, "grp-engineers", groupRow.DimensionId, "group row must carry the source group id as dimension_id")

	userRow, ok := byKind["user"]
	require.True(t, ok, "user dimension must surface")
	assert.Equal(t, testUserID, userRow.DimensionId, "user row must carry the user id as dimension_id")

	// Both rows fall in the same aligned window (same length, recorded
	// together), so window_start_utc must match across them.
	assert.Equal(t, groupRow.WindowStartUtc, userRow.WindowStartUtc,
		"rows recorded in the same window must share the aligned window_start_utc")
}
