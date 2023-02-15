package http

import (
	"net/http"

	"github.com/gorilla/mux"
	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/rs/cors"
)

// AuthCfg contains parameters for authentication middleware
type AuthCfg struct {
	Issuer       string
	Audience     string
	UserIDClaim  string
	KeysLocation string
}

// APIHandler creates the Management service HTTP API handler registering all the available endpoints.
func APIHandler(accountManager s.AccountManager, appMetrics telemetry.AppMetrics, authCfg AuthCfg) (http.Handler, error) {
	jwtMiddleware, err := middleware.NewJwtMiddleware(
		authCfg.Issuer,
		authCfg.Audience,
		authCfg.KeysLocation)
	if err != nil {
		return nil, err
	}

	corsMiddleware := cors.AllowAll()

	acMiddleware := middleware.NewAccessControl(
		authCfg.Audience,
		authCfg.UserIDClaim,
		accountManager.IsUserAdmin)

	rootRouter := mux.NewRouter()
	metricsMiddleware := appMetrics.HTTPMiddleware()

	apiHandler := rootRouter.PathPrefix("/api").Subrouter()
	apiHandler.Use(metricsMiddleware.Handler, corsMiddleware.Handler, jwtMiddleware.Handler, acMiddleware.Handler)

	groupsHandler := NewGroups(accountManager, authCfg)
	rulesHandler := NewRules(accountManager, authCfg)
	peersHandler := NewPeers(accountManager, authCfg)
	keysHandler := NewSetupKeysHandler(accountManager, authCfg)
	userHandler := NewUserHandler(accountManager, authCfg)
	routesHandler := NewRoutes(accountManager, authCfg)
	nameserversHandler := NewNameservers(accountManager, authCfg)
	eventsHandler := NewEvents(accountManager, authCfg)
	dnsSettingsHandler := NewDNSSettings(accountManager, authCfg)
	accountsHandler := NewAccounts(accountManager, authCfg)

	apiHandler.HandleFunc("/accounts/{id}", accountsHandler.UpdateAccountHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/accounts", accountsHandler.GetAccountsHandler).Methods("GET", "OPTIONS")

	apiHandler.HandleFunc("/peers", peersHandler.GetPeers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/peers/{id}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
	apiHandler.HandleFunc("/users", userHandler.GetUsers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/users/{id}", userHandler.UpdateUser).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/users", userHandler.CreateUserHandler).Methods("POST", "OPTIONS")

	apiHandler.HandleFunc("/setup-keys", keysHandler.GetAllSetupKeysHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/setup-keys", keysHandler.CreateSetupKeyHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/setup-keys/{id}", keysHandler.GetSetupKeyHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/setup-keys/{id}", keysHandler.UpdateSetupKeyHandler).Methods("PUT", "OPTIONS")

	apiHandler.HandleFunc("/rules", rulesHandler.GetAllRulesHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/rules", rulesHandler.CreateRuleHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.UpdateRuleHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.PatchRuleHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.GetRuleHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.DeleteRuleHandler).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/groups", groupsHandler.GetAllGroupsHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/groups", groupsHandler.CreateGroupHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.UpdateGroupHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.PatchGroupHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.GetGroupHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.DeleteGroupHandler).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/routes", routesHandler.GetAllRoutesHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/routes", routesHandler.CreateRouteHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.UpdateRouteHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.PatchRouteHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.GetRouteHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.DeleteRouteHandler).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/dns/nameservers", nameserversHandler.GetAllNameserversHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers", nameserversHandler.CreateNameserverGroupHandler).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.UpdateNameserverGroupHandler).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.PatchNameserverGroupHandler).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.GetNameserverGroupHandler).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.DeleteNameserverGroupHandler).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/events", eventsHandler.GetEvents).Methods("GET", "OPTIONS")

	apiHandler.HandleFunc("/dns/settings", dnsSettingsHandler.GetDNSSettings).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/dns/settings", dnsSettingsHandler.UpdateDNSSettings).Methods("PUT", "OPTIONS")

	err = apiHandler.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		methods, err := route.GetMethods()
		if err != nil {
			return err
		}
		for _, method := range methods {
			template, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			err = metricsMiddleware.AddHTTPRequestResponseCounter(template, method)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return rootRouter, nil
}
