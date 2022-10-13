package http

import (
	"github.com/gorilla/mux"
	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/rs/cors"
	"net/http"
)

// APIHandler creates the Management service HTTP API handler registering all the available endpoints.
func APIHandler(accountManager s.AccountManager, authIssuer string, authAudience string, authKeysLocation string) (http.Handler, error) {
	jwtMiddleware, err := middleware.NewJwtMiddleware(
		authIssuer,
		authAudience,
		authKeysLocation,
	)
	if err != nil {
		return nil, err
	}

	corsMiddleware := cors.AllowAll()

	acMiddleware := middleware.NewAccessControll(
		authAudience,
		accountManager.IsUserAdmin)

	apiHandler := mux.NewRouter()
	apiHandler.Use(corsMiddleware.Handler, jwtMiddleware.Handler, acMiddleware.Handler)

	groupsHandler := NewGroups(accountManager, authAudience)
	rulesHandler := NewRules(accountManager, authAudience)
	peersHandler := NewPeers(accountManager, authAudience)
	keysHandler := NewSetupKeysHandler(accountManager, authAudience)
	userHandler := NewUserHandler(accountManager, authAudience)
	routesHandler := NewRoutes(accountManager, authAudience)
	nameserversHandler := NewNameservers(accountManager, authAudience)

	apiHandler.HandleFunc("/api/peers", peersHandler.GetPeers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/peers/{id}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
	apiHandler.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/users/{id}", userHandler.UpdateUser).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/api/users", userHandler.CreateUserHandler).Methods("POST", "OPTIONS")

	apiHandler.HandleFunc("/api/setup-keys", keysHandler.GetAllSetupKeysHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/setup-keys", keysHandler.CreateSetupKeyHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/api/setup-keys/{id}", keysHandler.GetSetupKeyHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/setup-keys/{id}", keysHandler.UpdateSetupKeyHandler).Methods("PUT", "OPTIONS")

	apiHandler.HandleFunc("/api/rules", rulesHandler.GetAllRulesHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/rules", rulesHandler.CreateRuleHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/api/rules/{id}", rulesHandler.UpdateRuleHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/api/rules/{id}", rulesHandler.PatchRuleHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/api/rules/{id}", rulesHandler.GetRuleHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/rules/{id}", rulesHandler.DeleteRuleHandler).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/api/groups", groupsHandler.GetAllGroupsHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/groups", groupsHandler.CreateGroupHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/api/groups/{id}", groupsHandler.UpdateGroupHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/api/groups/{id}", groupsHandler.PatchGroupHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/api/groups/{id}", groupsHandler.GetGroupHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/groups/{id}", groupsHandler.DeleteGroupHandler).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/api/routes", routesHandler.GetAllRoutesHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/routes", routesHandler.CreateRouteHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/api/routes/{id}", routesHandler.UpdateRouteHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/api/routes/{id}", routesHandler.PatchRouteHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/api/routes/{id}", routesHandler.GetRouteHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/routes/{id}", routesHandler.DeleteRouteHandler).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/api/dns/nameservers", nameserversHandler.GetAllNameserversHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/dns/nameservers", nameserversHandler.CreateNameserverGroupHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/api/dns/nameservers/{id}", nameserversHandler.UpdateNameserverGroupHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/api/dns/nameservers/{id}", nameserversHandler.PatchNameserverGroupHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/api/dns/nameservers/{id}", nameserversHandler.GetNameserverGroupHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/dns/nameservers/{id}", nameserversHandler.DeleteNameserverGroupHandler).Methods("DELETE", "OPTIONS")

	return apiHandler, nil

}
