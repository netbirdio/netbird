package dns

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// dnsSettingsHandler is a handler that returns the DNS settings of the account
type dnsSettingsHandler struct {
	accountManager account.Manager
}

func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	addDNSSettingEndpoint(accountManager, router)
	addDNSNameserversEndpoint(accountManager, router)
}

func addDNSSettingEndpoint(accountManager account.Manager, router *mux.Router) {
	dnsSettingsHandler := newDNSSettingsHandler(accountManager)
	router.HandleFunc("/dns/settings", dnsSettingsHandler.getDNSSettings).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/settings", dnsSettingsHandler.updateDNSSettings).Methods("PUT", "OPTIONS")
}

// newDNSSettingsHandler returns a new instance of dnsSettingsHandler handler
func newDNSSettingsHandler(accountManager account.Manager) *dnsSettingsHandler {
	return &dnsSettingsHandler{accountManager: accountManager}
}

// getDNSSettings returns the DNS settings for the account
func (h *dnsSettingsHandler) getDNSSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	dnsSettings, err := h.accountManager.GetDNSSettings(r.Context(), accountID, userID)
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
func (h *dnsSettingsHandler) updateDNSSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.PutApiDnsSettingsJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	updateDNSSettings := &types.DNSSettings{
		DisabledManagementGroups: req.DisabledManagementGroups,
	}

	err = h.accountManager.SaveDNSSettings(r.Context(), accountID, userID, updateDNSSettings)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := api.DNSSettings{
		DisabledManagementGroups: updateDNSSettings.DisabledManagementGroups,
	}

	util.WriteJSONObject(r.Context(), w, &resp)
}
