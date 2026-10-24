package channel

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
)

// BuildApiBlackBoxWithRouters builds the API like BuildApiBlackBoxWithDBState, laid out the
// way BaseServer serves it: the shared middleware runs on the returned root router and the
// API sits on a /api subrouter without it. A handler mounted on apiRouter is authenticated by
// the root router, and a handler that dispatches to apiRouter in-process, as the MCP endpoint
// does, reaches the REST handlers on the identity already in the request context. Mount such
// handlers on apiRouter before serving requests through root.
func BuildApiBlackBoxWithRouters(t testing_tools.TB, sqlFile string) (root http.Handler, apiRouter *mux.Router, am account.Manager) {
	t.Helper()
	api := buildTestAPI(t, sqlFile, update_channel.NewPeersUpdateManager(nil))

	rootRouter := mux.NewRouter()
	rootRouter.Use(api.middleware()...)
	apiRouter = rootRouter.PathPrefix("/api").Subrouter()
	api.register(t, apiRouter)
	return rootRouter, apiRouter, api.am
}
