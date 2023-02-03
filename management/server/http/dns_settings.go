package http

import (
	"encoding/json"
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	log "github.com/sirupsen/logrus"
)

// DNSSettings is a handler that returns the DNS settings of the account
type DNSSettings struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewDNSSettings returns a new instance of DNSSettings handler
func NewDNSSettings(accountManager server.AccountManager, authCfg AuthCfg) *DNSSettings {
	return &DNSSettings{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetDNSSettings returns the DNS settings for the account
func (h *DNSSettings) GetDNSSettings(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	dnsSettings, err := h.accountManager.GetDNSSettings(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	apiDNSSettings := &api.DNSSettings{
		DisabledManagementGroups: dnsSettings.DisabledManagementGroups,
	}

	util.WriteJSONObject(w, apiDNSSettings)
}

// UpdateDNSSettings handles update to DNS settings of an account
func (h *DNSSettings) UpdateDNSSettings(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
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

	err = h.accountManager.SaveDNSSettings(account.Id, user.Id, updateDNSSettings)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := api.DNSSettings{
		DisabledManagementGroups: updateDNSSettings.DisabledManagementGroups,
	}

	util.WriteJSONObject(w, &resp)
}
