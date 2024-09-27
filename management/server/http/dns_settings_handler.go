package http

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

// DNSSettingsHandler is a handler that returns the DNS settings of the account
type DNSSettingsHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewDNSSettingsHandler returns a new instance of DNSSettingsHandler handler
func NewDNSSettingsHandler(accountManager server.AccountManager, authCfg AuthCfg) *DNSSettingsHandler {
	return &DNSSettingsHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetDNSSettings returns the DNS settings for the account
func (h *DNSSettingsHandler) GetDNSSettings(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

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

// UpdateDNSSettings handles update to DNS settings of an account
func (h *DNSSettingsHandler) UpdateDNSSettings(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PutApiDnsSettingsJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	updateDNSSettings := &server.DNSSettings{
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
