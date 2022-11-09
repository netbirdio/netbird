package http

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/rs/xid"
	"net/http"
)

// Rules is a handler that returns rules of the account
type Rules struct {
	jwtExtractor   jwtclaims.ClaimsExtractor
	accountManager server.AccountManager
	authAudience   string
}

func NewRules(accountManager server.AccountManager, authAudience string) *Rules {
	return &Rules{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// GetAllRulesHandler list for the account
func (h *Rules) GetAllRulesHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	accountRules, err := h.accountManager.ListRules(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	rules := []*api.Rule{}
	for _, r := range accountRules {
		rules = append(rules, toRuleResponse(account, r))
	}

	util.WriteJSONObject(w, rules)
}

// UpdateRuleHandler handles update to a rule identified by a given ID
func (h *Rules) UpdateRuleHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
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
		util.WriteError(status.Errorf(status.InvalidArgument, "couldn't parse JSON request"), w)
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

	err = h.accountManager.SaveRule(account.Id, &rule)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRuleResponse(account, &rule)

	util.WriteJSONObject(w, &resp)
}

// PatchRuleHandler handles patch updates to a rule identified by a given ID
func (h *Rules) PatchRuleHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
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
		util.WriteError(status.Errorf(status.NotFound, "couldn't find rule ID %s", ruleID), w)
		return
	}

	var req api.PatchApiRulesIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "couldn't parse JSON request"), w)
		return
	}

	if len(req) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "no patch instruction received"), w)
		return
	}

	var operations []server.RuleUpdateOperation

	for _, patch := range req {
		switch patch.Path {
		case api.RulePatchOperationPathName:
			if patch.Op != api.RulePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"name field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			if len(patch.Value) == 0 || patch.Value[0] == "" {
				util.WriteError(status.Errorf(status.InvalidArgument, "rule name shouldn't be empty"), w)
				return
			}
			operations = append(operations, server.RuleUpdateOperation{
				Type:   server.UpdateRuleName,
				Values: patch.Value,
			})
		case api.RulePatchOperationPathDescription:
			if patch.Op != api.RulePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"description field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RuleUpdateOperation{
				Type:   server.UpdateRuleDescription,
				Values: patch.Value,
			})
		case api.RulePatchOperationPathFlow:
			if patch.Op != api.RulePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"flow field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RuleUpdateOperation{
				Type:   server.UpdateRuleFlow,
				Values: patch.Value,
			})
		case api.RulePatchOperationPathDisabled:
			if patch.Op != api.RulePatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"disabled field only accepts replace operation, got %s", patch.Op), w)
				return
			}
			operations = append(operations, server.RuleUpdateOperation{
				Type:   server.UpdateRuleStatus,
				Values: patch.Value,
			})
		case api.RulePatchOperationPathSources:
			switch patch.Op {
			case api.RulePatchOperationOpReplace:
				operations = append(operations, server.RuleUpdateOperation{
					Type:   server.UpdateSourceGroups,
					Values: patch.Value,
				})
			case api.RulePatchOperationOpRemove:
				operations = append(operations, server.RuleUpdateOperation{
					Type:   server.RemoveGroupsFromSource,
					Values: patch.Value,
				})
			case api.RulePatchOperationOpAdd:
				operations = append(operations, server.RuleUpdateOperation{
					Type:   server.InsertGroupsToSource,
					Values: patch.Value,
				})
			default:
				util.WriteError(status.Errorf(status.InvalidArgument,
					"invalid operation \"%s\" on Source field", patch.Op), w)
				return
			}
		case api.RulePatchOperationPathDestinations:
			switch patch.Op {
			case api.RulePatchOperationOpReplace:
				operations = append(operations, server.RuleUpdateOperation{
					Type:   server.UpdateDestinationGroups,
					Values: patch.Value,
				})
			case api.RulePatchOperationOpRemove:
				operations = append(operations, server.RuleUpdateOperation{
					Type:   server.RemoveGroupsFromDestination,
					Values: patch.Value,
				})
			case api.RulePatchOperationOpAdd:
				operations = append(operations, server.RuleUpdateOperation{
					Type:   server.InsertGroupsToDestination,
					Values: patch.Value,
				})
			default:
				util.WriteError(status.Errorf(status.InvalidArgument,
					"invalid operation \"%s\" on Destination field", patch.Op), w)
				return
			}
		default:
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid patch path"), w)
			return
		}
	}

	rule, err := h.accountManager.UpdateRule(account.Id, ruleID, operations)

	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRuleResponse(account, rule)

	util.WriteJSONObject(w, &resp)
}

// CreateRuleHandler handles rule creation request
func (h *Rules) CreateRuleHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PostApiRulesJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "couldn't parse JSON request"), w)
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

	err = h.accountManager.SaveRule(account.Id, &rule)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRuleResponse(account, &rule)

	util.WriteJSONObject(w, &resp)
}

// DeleteRuleHandler handles rule deletion request
func (h *Rules) DeleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
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

	err = h.accountManager.DeleteRule(aID, rID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, "")
}

// GetRuleHandler handles a group Get request identified by ID
func (h *Rules) GetRuleHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
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

		rule, err := h.accountManager.GetRule(account.Id, ruleID, user.Id)
		if err != nil {
			util.WriteError(status.Errorf(status.NotFound, "rule not found"), w)
			return
		}

		util.WriteJSONObject(w, toRuleResponse(account, rule))
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
