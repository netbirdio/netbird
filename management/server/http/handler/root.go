package handler

import (
	"github.com/gorilla/mux"
	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/rs/cors"
	"net/http"
)

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
	apiHandler.Use(jwtMiddleware.Handler, corsMiddleware.Handler, acMiddleware.Handler)

	groupsHandler := NewGroups(accountManager, authAudience)
	rulesHandler := NewRules(accountManager, authAudience)
	peersHandler := NewPeers(accountManager, authAudience)
	keysHandler := NewSetupKeysHandler(accountManager, authAudience)
	userHandler := NewUserHandler(accountManager, authAudience)

	apiHandler.HandleFunc("/api/peers", peersHandler.GetPeers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/peers/{id}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
	apiHandler.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET", "OPTIONS")
	apiHandler.HandleFunc("/api/setup-keys", keysHandler.GetKeys).Methods("GET", "POST", "OPTIONS")
	apiHandler.HandleFunc("/api/setup-keys/{id}", keysHandler.HandleKey).Methods("GET", "PUT", "OPTIONS")

	apiHandler.HandleFunc("/api/setup-keys", keysHandler.GetKeys).Methods("POST", "OPTIONS")
	apiHandler.HandleFunc("/api/setup-keys/{id}", keysHandler.HandleKey).
		Methods("GET", "PUT", "DELETE", "OPTIONS")

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

	return apiHandler, nil

}
