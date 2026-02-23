package dns

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// nameserversHandler is the nameserver group handler of the account
type nameserversHandler struct {
	accountManager account.Manager
}

func addDNSNameserversEndpoint(accountManager account.Manager, router *mux.Router, permissionsManager permissions.Manager) {
	nameserversHandler := newNameserversHandler(accountManager)
	router.HandleFunc("/dns/nameservers", permissionsManager.WithPermission(modules.Nameservers, operations.Read, nameserversHandler.getAllNameservers)).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/nameservers", permissionsManager.WithPermission(modules.Nameservers, operations.Create, nameserversHandler.createNameserverGroup)).Methods("POST", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", permissionsManager.WithPermission(modules.Nameservers, operations.Update, nameserversHandler.updateNameserverGroup)).Methods("PUT", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", permissionsManager.WithPermission(modules.Nameservers, operations.Read, nameserversHandler.getNameserverGroup)).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", permissionsManager.WithPermission(modules.Nameservers, operations.Delete, nameserversHandler.deleteNameserverGroup)).Methods("DELETE", "OPTIONS")
}

// newNameserversHandler returns a new instance of nameserversHandler handler
func newNameserversHandler(accountManager account.Manager) *nameserversHandler {
	return &nameserversHandler{accountManager: accountManager}
}

// getAllNameservers returns the list of nameserver groups for the account
func (h *nameserversHandler) getAllNameservers(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	nsGroups, err := h.accountManager.ListNameServerGroups(r.Context(), userAuth.AccountId, userAuth.UserId)
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
func (h *nameserversHandler) createNameserverGroup(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	var req api.PostApiDnsNameserversJSONRequestBody
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	nsList, err := toServerNSList(req.Nameservers)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	nsGroup, err := h.accountManager.CreateNameServerGroup(r.Context(), userAuth.AccountId, req.Name, req.Description, nsList, req.Groups, req.Primary, req.Domains, req.Enabled, userAuth.UserId, req.SearchDomainsEnabled)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// updateNameserverGroup handles update to a nameserver group identified by a given ID
func (h *nameserversHandler) updateNameserverGroup(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	var req api.PutApiDnsNameserversNsgroupIdJSONRequestBody
	err := json.NewDecoder(r.Body).Decode(&req)
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

	err = h.accountManager.SaveNameServerGroup(r.Context(), userAuth.AccountId, userAuth.UserId, updatedNSGroup)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(updatedNSGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// deleteNameserverGroup handles nameserver group deletion request
func (h *nameserversHandler) deleteNameserverGroup(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	err := h.accountManager.DeleteNameServerGroup(r.Context(), userAuth.AccountId, nsGroupID, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// getNameserverGroup handles a nameserver group Get request identified by ID
func (h *nameserversHandler) getNameserverGroup(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	nsGroup, err := h.accountManager.GetNameServerGroup(r.Context(), userAuth.AccountId, userAuth.UserId, nsGroupID)
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
