package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	log "github.com/sirupsen/logrus"
)

// Nameservers is the nameserver group handler of the account
type Nameservers struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewNameservers returns a new instance of Nameservers handler
func NewNameservers(accountManager server.AccountManager, authCfg AuthCfg) *Nameservers {
	return &Nameservers{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllNameserversHandler returns the list of nameserver groups for the account
func (h *Nameservers) GetAllNameserversHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	nsGroups, err := h.accountManager.ListNameServerGroups(account.Id)
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

// CreateNameserverGroupHandler handles nameserver group creation request
func (h *Nameservers) CreateNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {
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

	nsGroup, err := h.accountManager.CreateNameServerGroup(account.Id, req.Name, req.Description, nsList, req.Groups, req.Primary, req.Domains, req.Enabled, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(w, &resp)
}

// UpdateNameserverGroupHandler handles update to a nameserver group identified by a given ID
func (h *Nameservers) UpdateNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	nsGroupID := mux.Vars(r)["id"]
	if len(nsGroupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	var req api.PutApiDnsNameserversIdJSONRequestBody
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
		ID:          nsGroupID,
		Name:        req.Name,
		Description: req.Description,
		Primary:     req.Primary,
		Domains:     req.Domains,
		NameServers: nsList,
		Groups:      req.Groups,
		Enabled:     req.Enabled,
	}

	err = h.accountManager.SaveNameServerGroup(account.Id, user.Id, updatedNSGroup)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toNameserverGroupResponse(updatedNSGroup)

	util.WriteJSONObject(w, &resp)
}

// PatchNameserverGroupHandler handles patch updates to a nameserver group identified by a given ID
func (h *Nameservers) PatchNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	nsGroupID := mux.Vars(r)["id"]
	if len(nsGroupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	var req api.PatchApiDnsNameserversIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	var operations []server.NameServerGroupUpdateOperation
	for _, patch := range req {
		if patch.Op != api.NameserverGroupPatchOperationOpReplace {
			util.WriteError(status.Errorf(status.InvalidArgument,
				"nameserver groups only accepts replace operations, got %s", patch.Op), w)
			return
		}
		switch patch.Path {
		case api.NameserverGroupPatchOperationPathName:
			operations = append(operations, server.NameServerGroupUpdateOperation{
				Type:   server.UpdateNameServerGroupName,
				Values: patch.Value,
			})
		case api.NameserverGroupPatchOperationPathDescription:
			operations = append(operations, server.NameServerGroupUpdateOperation{
				Type:   server.UpdateNameServerGroupDescription,
				Values: patch.Value,
			})
		case api.NameserverGroupPatchOperationPathPrimary:
			operations = append(operations, server.NameServerGroupUpdateOperation{
				Type:   server.UpdateNameServerGroupPrimary,
				Values: patch.Value,
			})
		case api.NameserverGroupPatchOperationPathDomains:
			operations = append(operations, server.NameServerGroupUpdateOperation{
				Type:   server.UpdateNameServerGroupDomains,
				Values: patch.Value,
			})
		case api.NameserverGroupPatchOperationPathNameservers:
			operations = append(operations, server.NameServerGroupUpdateOperation{
				Type:   server.UpdateNameServerGroupNameServers,
				Values: patch.Value,
			})
		case api.NameserverGroupPatchOperationPathGroups:
			operations = append(operations, server.NameServerGroupUpdateOperation{
				Type:   server.UpdateNameServerGroupGroups,
				Values: patch.Value,
			})
		case api.NameserverGroupPatchOperationPathEnabled:
			operations = append(operations, server.NameServerGroupUpdateOperation{
				Type:   server.UpdateNameServerGroupEnabled,
				Values: patch.Value,
			})
		default:
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid patch path"), w)
			return
		}
	}

	updatedNSGroup, err := h.accountManager.UpdateNameServerGroup(account.Id, nsGroupID, user.Id, operations)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toNameserverGroupResponse(updatedNSGroup)

	util.WriteJSONObject(w, &resp)
}

// DeleteNameserverGroupHandler handles nameserver group deletion request
func (h *Nameservers) DeleteNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	nsGroupID := mux.Vars(r)["id"]
	if len(nsGroupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	err = h.accountManager.DeleteNameServerGroup(account.Id, nsGroupID, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, "")
}

// GetNameserverGroupHandler handles a nameserver group Get request identified by ID
func (h *Nameservers) GetNameserverGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	nsGroupID := mux.Vars(r)["id"]
	if len(nsGroupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	nsGroup, err := h.accountManager.GetNameServerGroup(account.Id, nsGroupID)
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
		Id:          serverNSGroup.ID,
		Name:        serverNSGroup.Name,
		Description: serverNSGroup.Description,
		Primary:     serverNSGroup.Primary,
		Domains:     serverNSGroup.Domains,
		Groups:      serverNSGroup.Groups,
		Nameservers: nsList,
		Enabled:     serverNSGroup.Enabled,
	}
}
