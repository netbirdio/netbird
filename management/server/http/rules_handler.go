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

// RulesHandler is a handler that returns rules of the account
type RulesHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewRulesHandler creates a new RulesHandler HTTP handler
func NewRulesHandler(accountManager server.AccountManager, authCfg AuthCfg) *RulesHandler {
	return &RulesHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllRules list for the account
func (h *RulesHandler) GetAllRules(w http.ResponseWriter, r *http.Request) {
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
	rules := []*api.Rule{}
	for _, policy := range accountPolicies {
		for _, r := range policy.Rules {
			rules = append(rules, toRuleResponse(account, r.ToRule()))
		}
	}

	util.WriteJSONObject(w, rules)
}

// UpdateRule handles update to a rule identified by a given ID
func (h *RulesHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	ruleID := vars["id"]
	if len(ruleID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid rule ID"), w)
		return
	}

	_, ok := account.Rules[ruleID]
	if !ok {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find rule id %s", ruleID), w)
		return
	}

	var req api.PutApiRulesIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "rule name shouldn't be empty"), w)
		return
	}

	var reqSources []string
	if req.Sources != nil {
		reqSources = *req.Sources
	}

	var reqDestinations []string
	if req.Destinations != nil {
		reqDestinations = *req.Destinations
	}

	rule := server.Rule{
		ID:          ruleID,
		Name:        req.Name,
		Source:      reqSources,
		Destination: reqDestinations,
		Disabled:    req.Disabled,
		Description: req.Description,
	}

	switch req.Flow {
	case server.TrafficFlowBidirectString:
		rule.Flow = server.TrafficFlowBidirect
	default:
		util.WriteError(status.Errorf(status.InvalidArgument, "unknown flow type"), w)
		return
	}

	policy, err := server.RuleToPolicy(&rule)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	err = h.accountManager.SavePolicy(account.Id, user.Id, policy)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRuleResponse(account, policy.Rules[0].ToRule())

	util.WriteJSONObject(w, &resp)
}

// CreateRule handles rule creation request
func (h *RulesHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PostApiRulesJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "rule name shouldn't be empty"), w)
		return
	}

	var reqSources []string
	if req.Sources != nil {
		reqSources = *req.Sources
	}

	var reqDestinations []string
	if req.Destinations != nil {
		reqDestinations = *req.Destinations
	}

	rule := server.Rule{
		ID:          xid.New().String(),
		Name:        req.Name,
		Source:      reqSources,
		Destination: reqDestinations,
		Disabled:    req.Disabled,
		Description: req.Description,
	}

	switch req.Flow {
	case server.TrafficFlowBidirectString:
		rule.Flow = server.TrafficFlowBidirect
	default:
		util.WriteError(status.Errorf(status.InvalidArgument, "unknown flow type"), w)
		return
	}

	policy, err := server.RuleToPolicy(&rule)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	err = h.accountManager.SavePolicy(account.Id, user.Id, policy)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRuleResponse(account, &rule)

	util.WriteJSONObject(w, &resp)
}

// DeleteRule handles rule deletion request
func (h *RulesHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	aID := account.Id

	rID := mux.Vars(r)["id"]
	if len(rID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid rule ID"), w)
		return
	}

	err = h.accountManager.DeletePolicy(aID, rID, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, "")
}

// GetRule handles a group Get request identified by ID
func (h *RulesHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		ruleID := mux.Vars(r)["id"]
		if len(ruleID) == 0 {
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid rule ID"), w)
			return
		}

		policy, err := h.accountManager.GetPolicy(account.Id, ruleID, user.Id)
		if err != nil {
			util.WriteError(status.Errorf(status.NotFound, "rule not found"), w)
			return
		}

		util.WriteJSONObject(w, toRuleResponse(account, policy.Rules[0].ToRule()))
	default:
		util.WriteError(status.Errorf(status.NotFound, "method not found"), w)
	}
}

func toRuleResponse(account *server.Account, rule *server.Rule) *api.Rule {
	cache := make(map[string]api.GroupMinimum)
	gr := api.Rule{
		Id:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		Disabled:    rule.Disabled,
	}

	switch rule.Flow {
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
