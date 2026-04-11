package inspection

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// Handler manages inspection policy CRUD operations.
type Handler struct {
	accountManager account.Manager
}

// AddEndpoints registers the inspection policy API endpoints.
func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &Handler{accountManager: accountManager}
	router.HandleFunc("/inspection-policies", h.list).Methods("GET", "OPTIONS")
	router.HandleFunc("/inspection-policies", h.create).Methods("POST", "OPTIONS")
	router.HandleFunc("/inspection-policies/{policyId}", h.get).Methods("GET", "OPTIONS")
	router.HandleFunc("/inspection-policies/{policyId}", h.update).Methods("PUT", "OPTIONS")
	router.HandleFunc("/inspection-policies/{policyId}", h.remove).Methods("DELETE", "OPTIONS")
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policies, err := h.accountManager.ListInspectionPolicies(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	result := make([]*api.InspectionPolicy, 0, len(policies))
	for _, p := range policies {
		result = append(result, toAPIResponse(p))
	}

	util.WriteJSONObject(r.Context(), w, result)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.InspectionPolicyMinimum
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "decode request: %v", err), w)
		return
	}

	policy := fromAPIRequest(&req)

	saved, err := h.accountManager.SaveInspectionPolicy(r.Context(), userAuth.AccountId, userAuth.UserId, policy, true)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(saved))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyID := mux.Vars(r)["policyId"]

	policy, err := h.accountManager.GetInspectionPolicy(r.Context(), userAuth.AccountId, policyID, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(policy))
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyID := mux.Vars(r)["policyId"]

	var req api.InspectionPolicyMinimum
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "decode request: %v", err), w)
		return
	}

	policy := fromAPIRequest(&req)
	policy.ID = policyID

	saved, err := h.accountManager.SaveInspectionPolicy(r.Context(), userAuth.AccountId, userAuth.UserId, policy, false)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(saved))
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyID := mux.Vars(r)["policyId"]

	if err := h.accountManager.DeleteInspectionPolicy(r.Context(), userAuth.AccountId, policyID, userAuth.UserId); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, struct{}{})
}

func toAPIResponse(p *types.InspectionPolicy) *api.InspectionPolicy {
	id := p.ID
	resp := &api.InspectionPolicy{
		Id:      &id,
		Name:    p.Name,
		Enabled: p.Enabled,
	}

	if p.Description != "" {
		resp.Description = &p.Description
	}
	if p.Mode != "" {
		mode := api.InspectionPolicyMode(p.Mode)
		resp.Mode = &mode
	}
	if p.ExternalURL != "" {
		resp.ExternalUrl = &p.ExternalURL
	}
	if p.DefaultAction != "" {
		da := api.InspectionPolicyDefaultAction(p.DefaultAction)
		resp.DefaultAction = &da
	}
	if len(p.RedirectPorts) > 0 {
		resp.RedirectPorts = &p.RedirectPorts
	}
	if p.CACertPEM != "" {
		resp.CaCertPem = &p.CACertPEM
	}
	if p.CAKeyPEM != "" {
		resp.CaKeyPem = &p.CAKeyPEM
	}
	if p.EnvoyBinaryPath != "" {
		resp.EnvoyBinaryPath = &p.EnvoyBinaryPath
	}
	if p.EnvoyAdminPort != 0 {
		port := int(p.EnvoyAdminPort)
		resp.EnvoyAdminPort = &port
	}
	if p.ICAP != nil {
		resp.Icap = &api.InspectionICAPConfig{}
		if p.ICAP.ReqModURL != "" {
			resp.Icap.ReqmodUrl = &p.ICAP.ReqModURL
		}
		if p.ICAP.RespModURL != "" {
			resp.Icap.RespmodUrl = &p.ICAP.RespModURL
		}
		if p.ICAP.MaxConnections != 0 {
			resp.Icap.MaxConnections = &p.ICAP.MaxConnections
		}
	}

	rules := make([]api.InspectionPolicyRule, 0, len(p.Rules))
	for _, r := range p.Rules {
		rule := api.InspectionPolicyRule{
			Action:   api.InspectionPolicyRuleAction(r.Action),
			Priority: r.Priority,
		}
		if len(r.Domains) > 0 {
			rule.Domains = &r.Domains
		}
		if len(r.Networks) > 0 {
			rule.Networks = &r.Networks
		}
		if len(r.Protocols) > 0 {
			protos := make([]api.InspectionPolicyRuleProtocols, len(r.Protocols))
			for i, proto := range r.Protocols {
				protos[i] = api.InspectionPolicyRuleProtocols(proto)
			}
			rule.Protocols = &protos
		}
		if len(r.Paths) > 0 {
			rule.Paths = &r.Paths
		}
		rules = append(rules, rule)
	}
	resp.Rules = rules

	return resp
}

func fromAPIRequest(req *api.InspectionPolicyMinimum) *types.InspectionPolicy {
	p := &types.InspectionPolicy{
		Name:    req.Name,
		Enabled: req.Enabled,
	}

	if req.Description != nil {
		p.Description = *req.Description
	}
	if req.Mode != nil {
		p.Mode = string(*req.Mode)
	}
	if req.ExternalUrl != nil {
		p.ExternalURL = *req.ExternalUrl
	}
	if req.DefaultAction != nil {
		p.DefaultAction = string(*req.DefaultAction)
	}
	if req.RedirectPorts != nil {
		p.RedirectPorts = *req.RedirectPorts
	}
	if req.CaCertPem != nil {
		p.CACertPEM = *req.CaCertPem
	}
	if req.CaKeyPem != nil {
		p.CAKeyPEM = *req.CaKeyPem
	}
	if req.EnvoyBinaryPath != nil {
		p.EnvoyBinaryPath = *req.EnvoyBinaryPath
	}
	if req.EnvoyAdminPort != nil {
		p.EnvoyAdminPort = *req.EnvoyAdminPort
	}
	if req.Icap != nil {
		p.ICAP = &types.InspectionICAPConfig{}
		if req.Icap.ReqmodUrl != nil {
			p.ICAP.ReqModURL = *req.Icap.ReqmodUrl
		}
		if req.Icap.RespmodUrl != nil {
			p.ICAP.RespModURL = *req.Icap.RespmodUrl
		}
		if req.Icap.MaxConnections != nil {
			p.ICAP.MaxConnections = *req.Icap.MaxConnections
		}
	}

	for _, r := range req.Rules {
		rule := types.InspectionPolicyRule{
			Action:   string(r.Action),
			Priority: r.Priority,
		}
		if r.Domains != nil {
			rule.Domains = *r.Domains
		}
		if r.Networks != nil {
			rule.Networks = *r.Networks
		}
		if r.Protocols != nil {
			for _, proto := range *r.Protocols {
				rule.Protocols = append(rule.Protocols, string(proto))
			}
		}
		if r.Paths != nil {
			rule.Paths = *r.Paths
		}
		p.Rules = append(p.Rules, rule)
	}

	return p
}
