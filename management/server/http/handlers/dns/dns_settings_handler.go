package dns

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/permissions"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/modules"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/operations"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// dnsSettingsHandler is a handler that returns the DNS settings of the account
type dnsSettingsHandler struct {
	accountManager account.Manager
}

func AddEndpoints(accountManager account.Manager, router *mux.Router, permissionsManager permissions.Manager) {
	addDNSSettingEndpoint(accountManager, router, permissionsManager)
	addDNSNameserversEndpoint(accountManager, router, permissionsManager)
}

func addDNSSettingEndpoint(accountManager account.Manager, router *mux.Router, permissionsManager permissions.Manager) {
	dnsSettingsHandler := newDNSSettingsHandler(accountManager)
	router.HandleFunc("/dns/settings", permissionsManager.WithPermission(modules.Dns, operations.Read, dnsSettingsHandler.getDNSSettings)).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/settings", permissionsManager.WithPermission(modules.Dns, operations.Update, dnsSettingsHandler.updateDNSSettings)).Methods("PUT", "OPTIONS")
}

// newDNSSettingsHandler returns a new instance of dnsSettingsHandler handler
func newDNSSettingsHandler(accountManager account.Manager) *dnsSettingsHandler {
	return &dnsSettingsHandler{accountManager: accountManager}
}

// getDNSSettings returns the DNS settings for the account
func (h *dnsSettingsHandler) getDNSSettings(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	dnsSettings, err := h.accountManager.GetDNSSettings(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiDNSSettings := &api.DNSSettings{
		DisabledManagementGroups: dnsSettings.DisabledManagementGroups,
	}

	util.WriteJSONObject(r.Context(), w, apiDNSSettings)
}

// updateDNSSettings handles update to DNS settings of an account
func (h *dnsSettingsHandler) updateDNSSettings(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	var req api.PutApiDnsSettingsJSONRequestBody
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	updateDNSSettings := &types.DNSSettings{
		DisabledManagementGroups: req.DisabledManagementGroups,
	}

	err = h.accountManager.SaveDNSSettings(r.Context(), userAuth.AccountId, userAuth.UserId, updateDNSSettings)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := api.DNSSettings{
		DisabledManagementGroups: updateDNSSettings.DisabledManagementGroups,
	}

	util.WriteJSONObject(r.Context(), w, &resp)
}
