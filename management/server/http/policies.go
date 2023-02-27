package http

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/xid"

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

	var req api.PutApiPoliciesIdJSONRequestBody
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
		Query:       req.Query,
	}
	if req.Meta != nil {
		policy.Meta = &server.PolicyMeta{
			Destinations: toGroupMinimumsToGroups(account, req.Meta.Destinations),
			Sources:      toGroupMinimumsToGroups(account, req.Meta.Sources),
			Port:         req.Meta.Port,
		}
		switch req.Meta.Action {
		case api.PolicyMetaActionAccept:
			policy.Meta.Action = server.PolicyTrafficActionAccept
		case api.PolicyMetaActionDrop:
			policy.Meta.Action = server.PolicyTrafficActionDrop
		default:
			util.WriteError(status.Errorf(status.InvalidArgument, "unknown action type"), w)
			return
		}
	}

	if err = h.accountManager.SavePolicy(account.Id, user.Id, &policy); err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPolicyResponse(account, &policy))
}

// CreatePolicyHandler handles policy creation request
func (h *Policies) CreatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PostApiPoliciesJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "policy name shouldn't be empty"), w)
		return
	}

	policy := &server.Policy{
		ID:          xid.New().String(),
		Name:        req.Name,
		Disabled:    req.Disabled,
		Description: req.Description,
	}

	if req.Meta != nil {
		policy.Meta = &server.PolicyMeta{
			Destinations: toGroupMinimumsToGroups(account, req.Meta.Destinations),
			Sources:      toGroupMinimumsToGroups(account, req.Meta.Sources),
			Port:         req.Meta.Port,
		}
		switch req.Meta.Action {
		case api.PolicyMetaActionAccept:
			policy.Meta.Action = server.PolicyTrafficActionAccept
		case api.PolicyMetaActionDrop:
			policy.Meta.Action = server.PolicyTrafficActionDrop
		default:
			util.WriteError(status.Errorf(status.InvalidArgument, "unknown action type"), w)
			return
		}
	}

	if err = h.accountManager.SavePolicy(account.Id, user.Id, policy); err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPolicyResponse(account, policy))
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

		policy, err := h.accountManager.GetPolicy(account.Id, policyID, user.Id)
		if err != nil {
			util.WriteError(status.Errorf(status.NotFound, "policy not found"), w)
			return
		}

		util.WriteJSONObject(w, toPolicyResponse(account, policy))
	default:
		util.WriteError(status.Errorf(status.NotFound, "method not found"), w)
	}
}

func toPolicyResponse(account *server.Account, policy *server.Policy) *api.Policy {
	cache := make(map[string]api.GroupMinimum)
	ap := &api.Policy{
		Id:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		Disabled:    policy.Disabled,
		Query:       policy.Query,
	}
	if policy.Meta == nil {
		return ap
	}

	ap.Meta = &api.PolicyMeta{
		Port:   policy.Meta.Port,
		Action: api.PolicyMetaAction(policy.Meta.Action),
	}

	for _, gid := range policy.Meta.Sources {
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

			ap.Meta.Sources = append(ap.Meta.Sources, minimum)
			cache[gid] = minimum
		}
	}

	for _, gid := range policy.Meta.Destinations {
		cachedMinimum, ok := cache[gid]
		if ok {
			ap.Meta.Destinations = append(ap.Meta.Destinations, cachedMinimum)
			continue
		}
		if group, ok := account.Groups[gid]; ok {
			minimum := api.GroupMinimum{
				Id:         group.ID,
				Name:       group.Name,
				PeersCount: len(group.Peers),
			}
			ap.Meta.Destinations = append(ap.Meta.Destinations, minimum)
			cache[gid] = minimum
		}
	}

	return ap
}

func toGroupMinimumsToGroups(account *server.Account, gm []api.GroupMinimum) []string {
	result := make([]string, 0, len(gm))
	for _, gm := range gm {
		if _, ok := account.Groups[gm.Id]; ok {
			continue
		}
		result = append(result, gm.Id)
	}
	return result
}
