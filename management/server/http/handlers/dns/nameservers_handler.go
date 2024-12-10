package dns

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// nameserversHandler is the nameserver group handler of the account
type nameserversHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func addDNSNameserversEndpoint(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	nameserversHandler := newNameserversHandler(accountManager, authCfg)
	router.HandleFunc("/dns/nameservers", nameserversHandler.getAllNameservers).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/nameservers", nameserversHandler.createNameserverGroup).Methods("POST", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.updateNameserverGroup).Methods("PUT", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.getNameserverGroup).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.deleteNameserverGroup).Methods("DELETE", "OPTIONS")
}

// newNameserversHandler returns a new instance of nameserversHandler handler
func newNameserversHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *nameserversHandler {
	return &nameserversHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// getAllNameservers returns the list of nameserver groups for the account
func (h *nameserversHandler) getAllNameservers(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	nsGroups, err := h.accountManager.ListNameServerGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiNameservers := make([]*api.NameserverGroup, 0)
	for _, r := range nsGroups {
		apiNameservers = append(apiNameservers, toNameserverGroupResponse(r))
	}

	util.WriteJSONObject(r.Context(), w, apiNameservers)
}

// createNameserverGroup handles nameserver group creation request
func (h *nameserversHandler) createNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PostApiDnsNameserversJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	nsList, err := toServerNSList(req.Nameservers)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	nsGroup, err := h.accountManager.CreateNameServerGroup(r.Context(), accountID, req.Name, req.Description, nsList, req.Groups, req.Primary, req.Domains, req.Enabled, userID, req.SearchDomainsEnabled)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// updateNameserverGroup handles update to a nameserver group identified by a given ID
func (h *nameserversHandler) updateNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	var req api.PutApiDnsNameserversNsgroupIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	nsList, err := toServerNSList(req.Nameservers)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	updatedNSGroup := &nbdns.NameServerGroup{
		ID:                   nsGroupID,
		Name:                 req.Name,
		Description:          req.Description,
		Primary:              req.Primary,
		Domains:              req.Domains,
		NameServers:          nsList,
		Groups:               req.Groups,
		Enabled:              req.Enabled,
		SearchDomainsEnabled: req.SearchDomainsEnabled,
	}

	err = h.accountManager.SaveNameServerGroup(r.Context(), accountID, userID, updatedNSGroup)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(updatedNSGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// deleteNameserverGroup handles nameserver group deletion request
func (h *nameserversHandler) deleteNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	err = h.accountManager.DeleteNameServerGroup(r.Context(), accountID, nsGroupID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// getNameserverGroup handles a nameserver group Get request identified by ID
func (h *nameserversHandler) getNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	nsGroup, err := h.accountManager.GetNameServerGroup(r.Context(), accountID, userID, nsGroupID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

func toServerNSList(apiNSList []api.Nameserver) ([]nbdns.NameServer, error) {
	var nsList []nbdns.NameServer
	for _, apiNS := range apiNSList {
		parsed, err := nbdns.ParseNameServerURL(fmt.Sprintf("%s://%s:%d", apiNS.NsType, apiNS.Ip, apiNS.Port))
		if err != nil {
			return nil, err
		}
		nsList = append(nsList, parsed)
	}

	return nsList, nil
}

func toNameserverGroupResponse(serverNSGroup *nbdns.NameServerGroup) *api.NameserverGroup {
	var nsList []api.Nameserver
	for _, ns := range serverNSGroup.NameServers {
		apiNS := api.Nameserver{
			Ip:     ns.IP.String(),
			NsType: api.NameserverNsType(ns.NSType.String()),
			Port:   ns.Port,
		}
		nsList = append(nsList, apiNS)
	}

	return &api.NameserverGroup{
		Id:                   serverNSGroup.ID,
		Name:                 serverNSGroup.Name,
		Description:          serverNSGroup.Description,
		Primary:              serverNSGroup.Primary,
		Domains:              serverNSGroup.Domains,
		Groups:               serverNSGroup.Groups,
		Nameservers:          nsList,
		Enabled:              serverNSGroup.Enabled,
		SearchDomainsEnabled: serverNSGroup.SearchDomainsEnabled,
	}
}
