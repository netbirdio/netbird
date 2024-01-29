package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// NameserversHandler is the nameserver group handler of the account
type NameserversHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewNameserversHandler returns a new instance of NameserversHandler handler
func NewNameserversHandler(accountManager server.AccountManager, authCfg AuthCfg) *NameserversHandler {
	return &NameserversHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllNameservers returns the list of nameserver groups for the account
func (h *NameserversHandler) GetAllNameservers(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	nsGroups, err := h.accountManager.ListNameServerGroups(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	apiNameservers := make([]*api.NameserverGroup, 0)
	for _, r := range nsGroups {
		apiNameservers = append(apiNameservers, toNameserverGroupResponse(r))
	}

	util.WriteJSONObject(w, apiNameservers)
}

// CreateNameserverGroup handles nameserver group creation request
func (h *NameserversHandler) CreateNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
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
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	nsGroup, err := h.accountManager.CreateNameServerGroup(account.Id, req.Name, req.Description, nsList, req.Groups, req.Primary, req.Domains, req.Enabled, user.Id, req.SearchDomainsEnabled)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(w, &resp)
}

// UpdateNameserverGroup handles update to a nameserver group identified by a given ID
func (h *NameserversHandler) UpdateNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
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
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
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

	err = h.accountManager.SaveNameServerGroup(account.Id, user.Id, updatedNSGroup)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toNameserverGroupResponse(updatedNSGroup)

	util.WriteJSONObject(w, &resp)
}

// DeleteNameserverGroup handles nameserver group deletion request
func (h *NameserversHandler) DeleteNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	err = h.accountManager.DeleteNameServerGroup(account.Id, nsGroupID, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, emptyObject{})
}

// GetNameserverGroup handles a nameserver group Get request identified by ID
func (h *NameserversHandler) GetNameserverGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	nsGroup, err := h.accountManager.GetNameServerGroup(account.Id, user.Id, nsGroupID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(w, &resp)
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
