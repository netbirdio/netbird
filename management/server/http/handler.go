package http

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

// AuthCfg contains parameters for authentication middleware
type AuthCfg struct {
	Issuer       string
	Audience     string
	UserIDClaim  string
	KeysLocation string
}

type apiHandler struct {
	Router         *mux.Router
	AccountManager s.AccountManager
	AuthCfg        AuthCfg
}

// EmptyObject is an empty struct used to return empty JSON object
type emptyObject struct {
}

// APIHandler creates the Management service HTTP API handler registering all the available endpoints.
func APIHandler(accountManager s.AccountManager, jwtValidator jwtclaims.JWTValidator, appMetrics telemetry.AppMetrics, authCfg AuthCfg) (http.Handler, error) {
	authMiddleware := middleware.NewAuthMiddleware(
		accountManager.GetAccountFromPAT,
		jwtValidator.ValidateAndParse,
		accountManager.MarkPATUsed,
		authCfg.Audience)

	corsMiddleware := cors.AllowAll()

	acMiddleware := middleware.NewAccessControl(
		authCfg.Audience,
		authCfg.UserIDClaim,
		accountManager.GetUser)

	rootRouter := mux.NewRouter()
	metricsMiddleware := appMetrics.HTTPMiddleware()

	router := rootRouter.PathPrefix("/api").Subrouter()
	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler, acMiddleware.Handler)

	api := apiHandler{
		Router:         router,
		AccountManager: accountManager,
		AuthCfg:        authCfg,
	}

	api.addAccountsEndpoint()
	api.addPeersEndpoint()
	api.addUsersEndpoint()
	api.addUsersTokensEndpoint()
	api.addSetupKeysEndpoint()
	api.addRulesEndpoint()
	api.addPoliciesEndpoint()
	api.addGroupsEndpoint()
	api.addRoutesEndpoint()
	api.addDNSNameserversEndpoint()
	api.addDNSSettingEndpoint()
	api.addEventsEndpoint()

	err := api.Router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
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

func (apiHandler *apiHandler) addAccountsEndpoint() {
	accountsHandler := NewAccountsHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/accounts/{accountId}", accountsHandler.UpdateAccount).Methods("PUT", "OPTIONS")
	apiHandler.Router.HandleFunc("/accounts", accountsHandler.GetAllAccounts).Methods("GET", "OPTIONS")
}

func (apiHandler *apiHandler) addPeersEndpoint() {
	peersHandler := NewPeersHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/peers", peersHandler.GetAllPeers).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/peers/{peerId}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
}

func (apiHandler *apiHandler) addUsersEndpoint() {
	userHandler := NewUsersHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/users", userHandler.GetAllUsers).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/users/{userId}", userHandler.UpdateUser).Methods("PUT", "OPTIONS")
	apiHandler.Router.HandleFunc("/users/{userId}", userHandler.DeleteUser).Methods("DELETE", "OPTIONS")
	apiHandler.Router.HandleFunc("/users", userHandler.CreateUser).Methods("POST", "OPTIONS")
}

func (apiHandler *apiHandler) addUsersTokensEndpoint() {
	tokenHandler := NewPATsHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/users/{userId}/tokens", tokenHandler.GetAllTokens).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/users/{userId}/tokens", tokenHandler.CreateToken).Methods("POST", "OPTIONS")
	apiHandler.Router.HandleFunc("/users/{userId}/tokens/{tokenId}", tokenHandler.GetToken).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/users/{userId}/tokens/{tokenId}", tokenHandler.DeleteToken).Methods("DELETE", "OPTIONS")
}

func (apiHandler *apiHandler) addSetupKeysEndpoint() {
	keysHandler := NewSetupKeysHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/setup-keys", keysHandler.GetAllSetupKeys).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/setup-keys", keysHandler.CreateSetupKey).Methods("POST", "OPTIONS")
	apiHandler.Router.HandleFunc("/setup-keys/{keyId}", keysHandler.GetSetupKey).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/setup-keys/{keyId}", keysHandler.UpdateSetupKey).Methods("PUT", "OPTIONS")
}

func (apiHandler *apiHandler) addRulesEndpoint() {
	rulesHandler := NewRulesHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/rules", rulesHandler.GetAllRules).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/rules", rulesHandler.CreateRule).Methods("POST", "OPTIONS")
	apiHandler.Router.HandleFunc("/rules/{ruleId}", rulesHandler.UpdateRule).Methods("PUT", "OPTIONS")
	apiHandler.Router.HandleFunc("/rules/{ruleId}", rulesHandler.GetRule).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/rules/{ruleId}", rulesHandler.DeleteRule).Methods("DELETE", "OPTIONS")
}

func (apiHandler *apiHandler) addPoliciesEndpoint() {
	policiesHandler := NewPoliciesHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/policies", policiesHandler.GetAllPolicies).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/policies", policiesHandler.CreatePolicy).Methods("POST", "OPTIONS")
	apiHandler.Router.HandleFunc("/policies/{policyId}", policiesHandler.UpdatePolicy).Methods("PUT", "OPTIONS")
	apiHandler.Router.HandleFunc("/policies/{policyId}", policiesHandler.GetPolicy).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/policies/{policyId}", policiesHandler.DeletePolicy).Methods("DELETE", "OPTIONS")
}

func (apiHandler *apiHandler) addGroupsEndpoint() {
	groupsHandler := NewGroupsHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/groups", groupsHandler.GetAllGroups).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/groups", groupsHandler.CreateGroup).Methods("POST", "OPTIONS")
	apiHandler.Router.HandleFunc("/groups/{groupId}", groupsHandler.UpdateGroup).Methods("PUT", "OPTIONS")
	apiHandler.Router.HandleFunc("/groups/{groupId}", groupsHandler.GetGroup).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/groups/{groupId}", groupsHandler.DeleteGroup).Methods("DELETE", "OPTIONS")
}

func (apiHandler *apiHandler) addRoutesEndpoint() {
	routesHandler := NewRoutesHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/routes", routesHandler.GetAllRoutes).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/routes", routesHandler.CreateRoute).Methods("POST", "OPTIONS")
	apiHandler.Router.HandleFunc("/routes/{routeId}", routesHandler.UpdateRoute).Methods("PUT", "OPTIONS")
	apiHandler.Router.HandleFunc("/routes/{routeId}", routesHandler.GetRoute).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/routes/{routeId}", routesHandler.DeleteRoute).Methods("DELETE", "OPTIONS")
}

func (apiHandler *apiHandler) addDNSNameserversEndpoint() {
	nameserversHandler := NewNameserversHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/dns/nameservers", nameserversHandler.GetAllNameservers).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/dns/nameservers", nameserversHandler.CreateNameserverGroup).Methods("POST", "OPTIONS")
	apiHandler.Router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.UpdateNameserverGroup).Methods("PUT", "OPTIONS")
	apiHandler.Router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.GetNameserverGroup).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.DeleteNameserverGroup).Methods("DELETE", "OPTIONS")
}

func (apiHandler *apiHandler) addDNSSettingEndpoint() {
	dnsSettingsHandler := NewDNSSettingsHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/dns/settings", dnsSettingsHandler.GetDNSSettings).Methods("GET", "OPTIONS")
	apiHandler.Router.HandleFunc("/dns/settings", dnsSettingsHandler.UpdateDNSSettings).Methods("PUT", "OPTIONS")
}

func (apiHandler *apiHandler) addEventsEndpoint() {
	eventsHandler := NewEventsHandler(apiHandler.AccountManager, apiHandler.AuthCfg)
	apiHandler.Router.HandleFunc("/events", eventsHandler.GetAllEvents).Methods("GET", "OPTIONS")
}
