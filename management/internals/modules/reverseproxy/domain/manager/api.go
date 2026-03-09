package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/permissions"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/modules"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/operations"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager Manager
}

func RegisterEndpoints(router *mux.Router, manager Manager, permissionsManager permissions.Manager) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/domains", permissionsManager.WithPermission(modules.Services, operations.Read, h.getAllDomains)).Methods("GET", "OPTIONS")
	router.HandleFunc("/domains", permissionsManager.WithPermission(modules.Services, operations.Create, h.createCustomDomain)).Methods("POST", "OPTIONS")
	router.HandleFunc("/domains/{domainId}", permissionsManager.WithPermission(modules.Services, operations.Delete, h.deleteCustomDomain)).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/domains/{domainId}/validate", permissionsManager.WithPermission(modules.Services, operations.Read, h.triggerCustomDomainValidation)).Methods("GET", "OPTIONS")
}

func domainTypeToApi(t domain.Type) api.ReverseProxyDomainType {
	switch t {
	case domain.TypeCustom:
		return api.ReverseProxyDomainTypeCustom
	case domain.TypeFree:
		return api.ReverseProxyDomainTypeFree
	}
	// By default return as a "free" domain as that is more restrictive.
	// TODO: is this correct?
	return api.ReverseProxyDomainTypeFree
}

func domainToApi(d *domain.Domain) api.ReverseProxyDomain {
	resp := api.ReverseProxyDomain{
		Domain:    d.Domain,
		Id:        d.ID,
		Type:      domainTypeToApi(d.Type),
		Validated: d.Validated,
	}
	if d.TargetCluster != "" {
		resp.TargetCluster = &d.TargetCluster
	}
	return resp
}

func (h *handler) getAllDomains(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	domains, err := h.manager.GetDomains(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ret := make([]api.ReverseProxyDomain, 0)
	for _, d := range domains {
		ret = append(ret, domainToApi(d))
	}

	util.WriteJSONObject(r.Context(), w, ret)
}

func (h *handler) createCustomDomain(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	var req api.PostApiReverseProxiesDomainsJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	domain, err := h.manager.CreateDomain(r.Context(), userAuth.AccountId, userAuth.UserId, req.Domain, req.TargetCluster)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, domainToApi(domain))
}

func (h *handler) deleteCustomDomain(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	domainID := mux.Vars(r)["domainId"]
	if domainID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "domain ID is required"), w)
		return
	}

	if err := h.manager.DeleteDomain(r.Context(), userAuth.AccountId, userAuth.UserId, domainID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) triggerCustomDomainValidation(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	domainID := mux.Vars(r)["domainId"]
	if domainID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "domain ID is required"), w)
		return
	}

	go h.manager.ValidateDomain(r.Context(), userAuth.AccountId, userAuth.UserId, domainID)

	w.WriteHeader(http.StatusAccepted)
}
