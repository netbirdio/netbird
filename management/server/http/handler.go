package http

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/telemetry"
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

	groupsHandler := NewGroupsHandler(accountManager, authCfg)
	rulesHandler := NewRulesHandler(accountManager, authCfg)
	peersHandler := NewPeersHandler(accountManager, authCfg)
	keysHandler := NewSetupKeysHandler(accountManager, authCfg)
	userHandler := NewUsersHandler(accountManager, authCfg)
	routesHandler := NewRoutesHandler(accountManager, authCfg)
	nameserversHandler := NewNameserversHandler(accountManager, authCfg)
	eventsHandler := NewEventsHandler(accountManager, authCfg)
	dnsSettingsHandler := NewDNSSettingsHandler(accountManager, authCfg)
	accountsHandler := NewAccountsHandler(accountManager, authCfg)

	apiHandler.HandleFunc("/accounts/{id}", accountsHandler.UpdateAccount).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/accounts", accountsHandler.GetAllAccounts).Methods("GET", "OPTIONS")

	apiHandler.HandleFunc("/peers", peersHandler.GetAllPeers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/peers/{id}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
	apiHandler.HandleFunc("/users", userHandler.GetAllUsers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/users/{id}", userHandler.UpdateUser).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/users", userHandler.CreateUser).Methods("POST", "OPTIONS")

	apiHandler.HandleFunc("/setup-keys", keysHandler.GetAllSetupKeys).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/setup-keys", keysHandler.CreateSetupKey).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/setup-keys/{id}", keysHandler.GetSetupKey).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/setup-keys/{id}", keysHandler.UpdateSetupKey).Methods("PUT", "OPTIONS")

	apiHandler.HandleFunc("/rules", rulesHandler.GetAllRules).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/rules", rulesHandler.CreateRule).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.UpdateRule).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.PatchRule).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.GetRule).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/rules/{id}", rulesHandler.DeleteRule).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/groups", groupsHandler.GetAllGroups).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/groups", groupsHandler.CreateGroup).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.UpdateGroup).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.PatchGroup).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.GetGroup).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/groups/{id}", groupsHandler.DeleteGroup).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/routes", routesHandler.GetAllRoutes).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/routes", routesHandler.CreateRoute).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.UpdateRoute).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.PatchRoute).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.GetRoute).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/routes/{id}", routesHandler.DeleteRoute).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/dns/nameservers", nameserversHandler.GetAllNameservers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers", nameserversHandler.CreateNameserverGroup).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.UpdateNameserverGroup).Methods("PUT", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.PatchNameserverGroup).Methods("PATCH", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.GetNameserverGroup).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/dns/nameservers/{id}", nameserversHandler.DeleteNameserverGroup).Methods("DELETE", "OPTIONS")

	apiHandler.HandleFunc("/events", eventsHandler.GetAllEvents).Methods("GET", "OPTIONS")

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
