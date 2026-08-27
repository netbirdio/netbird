package autonoma

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/store"
)

// The endpoint can delete an account, so the guards that decide whether it
// exists at all - and whether a given request is allowed to reach a factory -
// are the part worth pinning down. Everything below exercises those guards
// through the real router, with no manager behind them: a request that is
// rejected never reaches one, and a discover only reflects over the inputs.

// teardownCapableStore satisfies the cleaner assertion AddEndpoints makes.
// Nothing here is called: every request in this file is either rejected before
// it reaches a factory, or is a discover.
type teardownCapableStore struct{ store.Store }

func (teardownCapableStore) DeletePeerJobForTestData(context.Context, string, string) error {
	return nil
}
func (teardownCapableStore) DeleteProxyAccessTokenForTestData(context.Context, string, string) error {
	return nil
}
func (teardownCapableStore) DeleteAccessLogForTestData(context.Context, string, string) error {
	return nil
}
func (teardownCapableStore) DeleteProxyForTestData(context.Context, string, string) error {
	return nil
}
func (teardownCapableStore) DeleteAgentNetworkConsumptionForTestData(context.Context, string, agentNetworkTypes.ConsumptionDimension, string, int64, time.Time) error {
	return nil
}

// plainStore is a store without the scoped deletes teardown needs.
type plainStore struct{ store.Store }

type stubAccountManager struct{ account.Manager }

func testDeps() Deps {
	return Deps{AccountManager: stubAccountManager{}, Store: teardownCapableStore{}}
}

// mountedRouter registers the endpoint the way boot.go does, under /api.
func mountedRouter(t *testing.T, shared, signing string) *mux.Router {
	t.Helper()
	t.Setenv(sharedSecretEnv, shared)
	t.Setenv(signingSecretEnv, signing)

	router := mux.NewRouter().PathPrefix("/api").Subrouter()
	require.NoError(t, AddEndpoints(testDeps(), router))
	return router
}

// post sends body to the endpoint with the given signature header. An empty
// signature sends no header at all.
func post(router *mux.Router, body, signature string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api"+EndpointPath, strings.NewReader(body))
	if signature != "" {
		req.Header.Set("x-signature", signature)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// A deployment that has not opted in must not serve the route at all. This is
// the outermost guard: no secrets, no endpoint, regardless of anything else.
func TestTheEndpointIsNotRegisteredWithoutBothSecrets(t *testing.T) {
	for _, tc := range []struct{ name, shared, signing string }{
		{"neither", "", ""},
		{"only the shared secret", "shared-secret", ""},
		{"only the signing secret", "", "signing-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(sharedSecretEnv, tc.shared)
			t.Setenv(signingSecretEnv, tc.signing)

			router := mux.NewRouter().PathPrefix("/api").Subrouter()
			require.NoError(t, AddEndpoints(testDeps(), router))

			require.Equal(t, http.StatusNotFound, post(router, `{"action":"discover"}`, "").Code)
		})
	}
}

// Reusing one secret for both would let a caller that can sign a request also
// forge the teardown token, which is the whole point of having two.
func TestTheEndpointRefusesToStartWithOneSecretUsedTwice(t *testing.T) {
	t.Setenv(sharedSecretEnv, "same-secret")
	t.Setenv(signingSecretEnv, "same-secret")

	err := AddEndpoints(testDeps(), mux.NewRouter().PathPrefix("/api").Subrouter())
	require.ErrorContains(t, err, "must be different")
}

// Teardown reaches tables an account delete does not cascade into, so a store
// that cannot do those deletes would leave rows behind after every run.
func TestTheEndpointRefusesAStoreItCannotTearDownWith(t *testing.T) {
	t.Setenv(sharedSecretEnv, "shared-secret")
	t.Setenv(signingSecretEnv, "signing-secret")

	deps := testDeps()
	deps.Store = plainStore{}

	err := AddEndpoints(deps, mux.NewRouter().PathPrefix("/api").Subrouter())
	require.ErrorContains(t, err, "scoped test-data teardown")
}

// Every request carries an HMAC of its exact body. These are the three ways
// that can be wrong, and all of them have to stop before a factory runs.
func TestTheEndpointRejectsARequestItCannotVerify(t *testing.T) {
	const shared, signing = "shared-secret", "signing-secret"
	body := `{"action":"discover"}`

	t.Run("no signature at all", func(t *testing.T) {
		router := mountedRouter(t, shared, signing)
		require.Equal(t, http.StatusUnauthorized, post(router, body, "").Code)
	})

	t.Run("signed with the wrong secret", func(t *testing.T) {
		router := mountedRouter(t, shared, signing)
		wrong := sdk.SignBody(body, "not-the-shared-secret")
		require.Equal(t, http.StatusUnauthorized, post(router, body, wrong).Code)
	})

	t.Run("signed with the signing secret rather than the shared one", func(t *testing.T) {
		router := mountedRouter(t, shared, signing)
		require.Equal(t, http.StatusUnauthorized, post(router, body, sdk.SignBody(body, signing)).Code)
	})

	t.Run("body changed after it was signed", func(t *testing.T) {
		router := mountedRouter(t, shared, signing)
		signature := sdk.SignBody(body, shared)
		tampered := `{"action":"down"}`
		require.Equal(t, http.StatusUnauthorized, post(router, tampered, signature).Code)
	})
}

// The counterpart to the rejections: a correctly signed request gets through,
// and discover reports the factories a recipe may name.
func TestACorrectlySignedRequestReachesTheSDK(t *testing.T) {
	const shared, signing = "shared-secret", "signing-secret"
	router := mountedRouter(t, shared, signing)

	body := `{"action":"discover"}`
	rec := post(router, body, sdk.SignBody(body, shared))
	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotEmpty(t, payload, "discover should describe the factories")
}

// Every model a recipe can name needs a teardown, or `down` would leave its
// rows behind. A new factory that forgets one fails here rather than silently
// leaking rows on every run.
func TestEveryFactoryCanTearItsRowsDown(t *testing.T) {
	registry := (&factories{}).registry()
	require.NotEmpty(t, registry)

	for name, def := range registry {
		require.NotNil(t, def.Create, "%s has no create", name)
		require.NotNil(t, def.Teardown, "%s cannot be torn down", name)
		require.NotNil(t, def.InputStruct, "%s has no input struct", name)
	}
}
