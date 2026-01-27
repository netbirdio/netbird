package domains

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager manager
}

func RegisterEndpoints(router *mux.Router) {
	h := &handler{}

	router.HandleFunc("/domains", h.getAllDomains).Methods("GET", "OPTIONS")
	router.HandleFunc("/domains", h.createCustomDomain).Methods("POST", "OPTIONS")
	router.HandleFunc("/domains/{domainId}", h.deleteCustomDomain).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/domains/{domainId}/validate", h.triggerCustomDomainValidation).Methods("GET", "OPTIONS")
}

func domainTypeToApi(t domainType) api.ReverseProxyDomainType {
	switch t {
	case domainTypeCustom:
		return api.ReverseProxyDomainTypeCustom
	case domainTypeFree:
		return api.ReverseProxyDomainTypeFree
	}
	// By default return as a "free" domain as that is more restrictive.
	// TODO: is this correct?
	return api.ReverseProxyDomainTypeFree
}

func domainToApi(d domain) api.ReverseProxyDomain {
	return api.ReverseProxyDomain{
		Domain:    d.Domain,
		Id:        d.ID,
		Type:      domainTypeToApi(d.Type),
		Validated: d.Validated,
	}
}

func (h *handler) getAllDomains(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	domains, err := h.manager.GetDomains(r.Context(), userAuth.AccountId)

	var ret []api.ReverseProxyDomain
	for _, d := range domains {
		ret = append(ret, domainToApi(d))
	}

	util.WriteJSONObject(r.Context(), w, ret)
}

func (h *handler) createCustomDomain(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PostApiReverseProxyDomainsJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	domain, err := h.manager.CreateDomain(r.Context(), userAuth.AccountId, req.Domain)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, domainToApi(domain))
}

func (h *handler) deleteCustomDomain(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	domainID := mux.Vars(r)["domainId"]
	if domainID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "domain ID is required"), w)
		return
	}

	if err := h.manager.DeleteDomain(r.Context(), userAuth.AccountId, domainID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) triggerCustomDomainValidation(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	domainID := mux.Vars(r)["domainId"]
	if domainID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "domain ID is required"), w)
		return
	}

	go h.manager.ValidateDomain(userAuth.AccountId, domainID)

	w.WriteHeader(http.StatusAccepted)
}
