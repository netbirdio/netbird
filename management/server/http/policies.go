package http

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// Policies is a handler that returns policy of the account
type Policies struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func NewPolicies(accountManager server.AccountManager, authCfg AuthCfg) *Policies {
	return &Policies{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllPoliciesHandler list for the account
func (h *Policies) GetAllPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	accountPolicies, err := h.accountManager.ListPolicies(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, accountPolicies)
}

// UpdatePolicyHandler handles update to a policy identified by a given ID
func (h *Policies) UpdatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	policyID := vars["id"]
	if len(policyID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid policy ID"), w)
		return
	}

	policyIdx := -1
	for i, policy := range account.Policies {
		if policy.ID == policyID {
			policyIdx = i
			break
		}
	}
	if policyIdx < 0 {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find policy id %s", policyID), w)
		return
	}

	var req api.PutApiRulesIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "policy name shouldn't be empty"), w)
		return
	}

	policy := server.Policy{
		ID:          policyID,
		Name:        req.Name,
		Disabled:    req.Disabled,
		Description: req.Description,
	}

	err = h.accountManager.SavePolicy(account.Id, user.Id, &policy)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toPolicyResponse(account, &policy)

	// TODO: finish this
	util.WriteJSONObject(w, &resp)
}

// PatchPolicyHandler handles patch updates to a policy identified by a given ID
func (h *Policies) PatchPolicyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	policyID := vars["id"]
	if len(policyID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid policy ID"), w)
		return
	}

	policyIdx := -1
	for i, policy := range account.Policies {
		if policy.ID == policyID {
			policyIdx = i
			break
		}
	}
	if policyIdx < 0 {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find policy id %s", policyID), w)
		return
	}

	// TODO: finish this
	util.WriteJSONObject(w, nil)
}

// CreatePolicyHandler handles policy creation request
func (h *Policies) CreatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	_, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	// TODO: finish this
	util.WriteJSONObject(w, nil)
}

// DeletePolicyHandler handles policy deletion request
func (h *Policies) DeletePolicyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	aID := account.Id

	vars := mux.Vars(r)
	policyID := vars["id"]
	if len(policyID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid policy ID"), w)
		return
	}

	if err = h.accountManager.DeletePolicy(aID, policyID, user.Id); err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, "")
}

// GetPolicyHandler handles a group Get request identified by ID
func (h *Policies) GetPolicyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		vars := mux.Vars(r)
		policyID := vars["id"]
		if len(policyID) == 0 {
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid policy ID"), w)
			return
		}

		_, err := h.accountManager.GetRule(account.Id, policyID, user.Id)
		if err != nil {
			util.WriteError(status.Errorf(status.NotFound, "rule not found"), w)
			return
		}

		// TODO: finish this
		util.WriteJSONObject(w, nil)
	default:
		util.WriteError(status.Errorf(status.NotFound, "method not found"), w)
	}
}

func toPolicyResponse(account *server.Account, policy *server.Policy) *api.Rule {
	cache := make(map[string]api.GroupMinimum)
	gr := api.Policy{
		Id:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		Disabled:    policy.Disabled,
	}

	switch policy.Meta {
	case server.TrafficFlowBidirect:
		gr.Flow = server.TrafficFlowBidirectString
	default:
		gr.Flow = "unknown"
	}

	for _, gid := range rule.Source {
		_, ok := cache[gid]
		if ok {
			continue
		}

		if group, ok := account.Groups[gid]; ok {
			minimum := api.GroupMinimum{
				Id:         group.ID,
				Name:       group.Name,
				PeersCount: len(group.Peers),
			}

			gr.Sources = append(gr.Sources, minimum)
			cache[gid] = minimum
		}
	}

	for _, gid := range rule.Destination {
		cachedMinimum, ok := cache[gid]
		if ok {
			gr.Destinations = append(gr.Destinations, cachedMinimum)
			continue
		}
		if group, ok := account.Groups[gid]; ok {
			minimum := api.GroupMinimum{
				Id:         group.ID,
				Name:       group.Name,
				PeersCount: len(group.Peers),
			}
			gr.Destinations = append(gr.Destinations, minimum)
			cache[gid] = minimum
		}
	}

	return &gr
}
