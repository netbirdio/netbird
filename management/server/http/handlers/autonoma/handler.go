// Package autonoma exposes the Autonoma Environment Factory endpoint: one
// signed HTTP route that seeds a complete, isolated NetBird account before an
// end-to-end test run and removes it afterwards.
//
// The route is POST /api/autonoma, and it mounts itself only when both
// AUTONOMA_SHARED_SECRET and AUTONOMA_SIGNING_SECRET are in the environment - a
// deployment that does not opt in never serves it. Every request is HMAC-signed
// with the shared secret and verified by the SDK, and the teardown token that
// "down" presents is signed with the signing secret, so a teardown can only ever
// delete what its own "up" created.
//
// Every model is created through the same manager the product itself calls, so
// the seeded data carries the real validation, activity events, IdP records and
// network map updates a hand-made INSERT would skip. Teardown deletes the
// account and lets the graph go with it, including rows a test created mid-run
// that no recipe named; the few tables that hang off an account without a GORM
// association get scoped, idempotent deletes in
// management/server/store/sql_store_testdata.go.
//
// # Maintenance
//
// Add or update a factory whenever you add a model or change how one is
// created. A model with a new creation path, a new required field or a new
// invariant makes the matching factory wrong, and it shows up as a suite that
// cannot seed rather than as a compile error. Anything the app compares against
// the current time takes an offset as its factory input and derives the instant
// at seeding time - a recipe is stored once and replayed for months, so a stored
// timestamp goes stale.
//
// # Where a factory does not use a manager
//
// Job cannot go through DefaultAccountManager.CreatePeerJob, which refuses a
// peer with no live gRPC stream and pushes the job down that stream before
// persisting it; a seeded peer has no agent behind it. The factory builds the
// job with the product's own types.NewJob constructor and writes it with the
// same Store.CreatePeerJob call the manager's transaction makes, so the only
// skipped side effect is the push to an agent that is not there.
//
// A seeded Proxy has no process sending heartbeats, and a proxy counts as active
// only while its last heartbeat is under two minutes old. The factory stamps the
// heartbeat heartbeatValidForMinutes ahead instead (two hours by default), which
// keeps the cluster online for the length of a run.
package autonoma

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	domainmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/store"
)

const (
	// EndpointPath is the route the handler is mounted on, relative to the
	// /api prefix the management router already carries.
	EndpointPath = "/autonoma"

	// sharedSecretEnv is signed by Autonoma and verified here.
	sharedSecretEnv = "AUTONOMA_SHARED_SECRET" //nolint:gosec // an env var name, not a secret
	// signingSecretEnv never leaves the server; it signs the teardown token.
	signingSecretEnv = "AUTONOMA_SIGNING_SECRET"

	// scopeField names the column every seeded model hangs off, so the
	// dashboard knows how test data is isolated.
	scopeField = "accountId"

	// maxBodyBytes caps a request before it is read. The signature covers the
	// body, so verification cannot happen until the bytes are in memory, which
	// leaves the read itself reachable without authentication. A recipe that
	// seeds a whole account is a few hundred kilobytes; four megabytes leaves
	// room to grow without letting an unauthenticated caller decide how much
	// memory to take.
	maxBodyBytes = 4 << 20
)

// Deps carries the managers the factories create data through. Everything here
// is the production instance; the endpoint owns no storage of its own.
type Deps struct {
	AccountManager      account.Manager
	IdpManager          idp.Manager
	Store               store.Store
	NetworksManager     networks.Manager
	ResourcesManager    resources.Manager
	RoutersManager      routers.Manager
	ZonesManager        zones.Manager
	RecordsManager      records.Manager
	ServiceManager      service.Manager
	DomainManager       *domainmanager.Manager
	AccessLogsManager   accesslogs.Manager
	ProxyManager        proxy.Manager
	AgentNetworkManager agentnetwork.Manager
}

// cleaner is the narrow set of scoped deletes the teardown needs for tables an
// account delete does not cascade into. Implemented by *store.SqlStore.
type cleaner interface {
	DeletePeerJobForTestData(ctx context.Context, accountID, jobID string) error
	DeleteProxyAccessTokenForTestData(ctx context.Context, accountID, tokenID string) error
	DeleteAccessLogForTestData(ctx context.Context, accountID, logID string) error
	DeleteProxyForTestData(ctx context.Context, proxyID, sessionID string) error
	DeleteAgentNetworkConsumptionForTestData(ctx context.Context, accountID string, kind agentNetworkTypes.ConsumptionDimension, dimID string, windowSeconds int64, windowStart time.Time) error
}

// AddEndpoints mounts the Environment Factory endpoint when both Autonoma
// secrets are present in the environment. Absent secrets means the route is
// never registered at all: that is the production guard, and it is plain code
// here rather than a flag inside the SDK so it is obvious when the endpoint
// exists. HMAC verification of every request is the second gate, and the SDK
// applies it on our behalf.
func AddEndpoints(deps Deps, router *mux.Router) error {
	sharedSecret := os.Getenv(sharedSecretEnv)
	signingSecret := os.Getenv(signingSecretEnv)
	if sharedSecret == "" || signingSecret == "" {
		log.Infof("autonoma: test-data endpoint disabled, %s and %s are not both set", sharedSecretEnv, signingSecretEnv)
		return nil
	}
	if sharedSecret == signingSecret {
		return fmt.Errorf("autonoma: %s and %s must be different values", sharedSecretEnv, signingSecretEnv)
	}
	if deps.AccountManager == nil {
		return fmt.Errorf("autonoma: account manager is required")
	}

	c, ok := deps.Store.(cleaner)
	if !ok {
		return fmt.Errorf("autonoma: store does not support scoped test-data teardown")
	}

	// The endpoint authenticates itself with the HMAC signature the SDK
	// verifies, so it must not go through the JWT/PAT middleware.
	if err := bypass.AddBypassPath("/api" + EndpointPath); err != nil {
		return fmt.Errorf("autonoma: add bypass path: %w", err)
	}

	router.HandleFunc(EndpointPath, handle(deps, c, sharedSecret, signingSecret)).Methods("POST", "OPTIONS")
	log.Infof("autonoma: test-data endpoint registered on /api%s with %d factories", EndpointPath, len((&factories{}).registry()))

	return nil
}

// configFor builds the per-request handler config. The factories are rebuilt
// each time because they carry the request's context, which is what lets a
// manager call log and trace against the request that asked for it.
func configFor(deps Deps, c cleaner, sharedSecret, signingSecret string, ctx context.Context) *sdk.HandlerConfig {
	f := &factories{deps: deps, cleaner: c, ctx: ctx}
	return &sdk.HandlerConfig{
		ScopeField:    scopeField,
		SharedSecret:  sharedSecret,
		SigningSecret: signingSecret,
		SDK:           &sdk.SdkInfo{Orm: "gorm", Server: "gorilla-mux"},
		Factories:     f.registry(),
		Auth:          f.auth,
	}
}

// handle adapts the SDK's framework-agnostic entry point to net/http. The SDK
// ships a Gin adapter only, and the management API is gorilla/mux, so the glue
// lives here: read the raw body (the signature covers the exact bytes),
// lower-case the header names the SDK looks up, and write back what it returns.
func handle(deps Deps, c cleaner, sharedSecret, signingSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Seeding must survive the caller hanging up: rows already written
		// would otherwise be orphaned, since the refs that tear them down only
		// reach the caller in the response.
		config := configFor(deps, c, sharedSecret, signingSecret, context.WithoutCancel(r.Context()))

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
					"error": "request body exceeds the limit",
					"code":  "PAYLOAD_TOO_LARGE",
				})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "failed to read request body",
				"code":  "INTERNAL_ERROR",
			})
			return
		}

		headers := make(map[string]string, len(r.Header))
		for name, values := range r.Header {
			if len(values) > 0 {
				headers[strings.ToLower(name)] = values[0]
			}
		}

		result := sdk.HandleRequest(config, sdk.HandlerRequest{Body: string(body), Headers: headers})
		if result.Status >= http.StatusBadRequest {
			log.WithContext(r.Context()).Warnf("autonoma: request failed with %d: %v", result.Status, result.Body["error"])
		}
		writeJSON(w, result.Status, result.Body)
	}
}
