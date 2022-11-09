package http

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
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
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	accountRules, err := h.accountManager.ListRules(account.Id, user.Id)
	if err != nil {
		log.Error(err)
		if e, ok := status.FromError(err); ok {
			switch e.Type() {
			case status.PermissionDenied:
				http.Error(w, e.Error(), http.StatusForbidden)
				return
			default:
			}
		}
		http.Redirect(w, r, "/", http.StatusInternalServerError)
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
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	ruleID := vars["id"]
	if len(ruleID) == 0 {
		http.Error(w, "invalid rule Id", http.StatusBadRequest)
		return
	}

	_, ok := account.Rules[ruleID]
	if !ok {
		http.Error(w, fmt.Sprintf("couldn't find rule id %s", ruleID), http.StatusNotFound)
		return
	}

	var req api.PutApiRulesIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Rule name shouldn't be empty", http.StatusUnprocessableEntity)
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
		http.Error(w, "unknown flow type", http.StatusBadRequest)
		return
	}

	if err := h.accountManager.SaveRule(account.Id, &rule); err != nil {
		log.Errorf("failed updating rule \"%s\" under account %s %v", ruleID, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
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
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	ruleID := vars["id"]
	if len(ruleID) == 0 {
		http.Error(w, "invalid rule Id", http.StatusBadRequest)
		return
	}

	_, ok := account.Rules[ruleID]
	if !ok {
		http.Error(w, fmt.Sprintf("couldn't find rule id %s", ruleID), http.StatusNotFound)
		return
	}

	var req api.PatchApiRulesIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req) == 0 {
		http.Error(w, "no patch instruction received", http.StatusBadRequest)
		return
	}

	var operations []server.RuleUpdateOperation

	for _, patch := range req {
		switch patch.Path {
		case api.RulePatchOperationPathName:
			if patch.Op != api.RulePatchOperationOpReplace {
				http.Error(w, fmt.Sprintf("Name field only accepts replace operation, got %s", patch.Op),
					http.StatusBadRequest)
				return
			}
			if len(patch.Value) == 0 || patch.Value[0] == "" {
				http.Error(w, "Rule name shouldn't be empty", http.StatusUnprocessableEntity)
				return
			}
			operations = append(operations, server.RuleUpdateOperation{
				Type:   server.UpdateRuleName,
				Values: patch.Value,
			})
		case api.RulePatchOperationPathDescription:
			if patch.Op != api.RulePatchOperationOpReplace {
				http.Error(w, fmt.Sprintf("Description field only accepts replace operation, got %s", patch.Op),
					http.StatusBadRequest)
				return
			}
			operations = append(operations, server.RuleUpdateOperation{
				Type:   server.UpdateRuleDescription,
				Values: patch.Value,
			})
		case api.RulePatchOperationPathFlow:
			if patch.Op != api.RulePatchOperationOpReplace {
				http.Error(w, fmt.Sprintf("Flow field only accepts replace operation, got %s", patch.Op),
					http.StatusBadRequest)
				return
			}
			operations = append(operations, server.RuleUpdateOperation{
				Type:   server.UpdateRuleFlow,
				Values: patch.Value,
			})
		case api.RulePatchOperationPathDisabled:
			if patch.Op != api.RulePatchOperationOpReplace {
				http.Error(w, fmt.Sprintf("Disabled field only accepts replace operation, got %s", patch.Op),
					http.StatusBadRequest)
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
				http.Error(w, "invalid operation, \"%s\", for Source field", http.StatusBadRequest)
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
				http.Error(w, "invalid operation, \"%s\", for Destination field", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "invalid patch path", http.StatusBadRequest)
			return
		}
	}

	rule, err := h.accountManager.UpdateRule(account.Id, ruleID, operations)

	if err != nil {
		errStatus, ok := status.FromError(err)
		if ok && errStatus.Type() == status.Internal {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if ok && errStatus.Type() == status.NotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if ok && errStatus.Type() == status.InvalidArgument {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Errorf("failed updating rule %s under account %s %v", ruleID, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
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
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var req api.PostApiRulesJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Rule name shouldn't be empty", http.StatusUnprocessableEntity)
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
		http.Error(w, "unknown flow type", http.StatusBadRequest)
		return
	}

	if err := h.accountManager.SaveRule(account.Id, &rule); err != nil {
		log.Errorf("failed creating rule \"%s\" under account %s %v", req.Name, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
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
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}
	aID := account.Id

	rID := mux.Vars(r)["id"]
	if len(rID) == 0 {
		http.Error(w, "invalid rule ID", http.StatusBadRequest)
		return
	}

	if err := h.accountManager.DeleteRule(aID, rID); err != nil {
		log.Errorf("failed delete rule %s under account %s %v", rID, aID, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	util.WriteJSONObject(w, "")
}

// GetRuleHandler handles a group Get request identified by ID
func (h *Rules) GetRuleHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		ruleID := mux.Vars(r)["id"]
		if len(ruleID) == 0 {
			http.Error(w, "invalid rule ID", http.StatusBadRequest)
			return
		}

		rule, err := h.accountManager.GetRule(account.Id, ruleID, user.Id)
		if err != nil {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}

		util.WriteJSONObject(w, toRuleResponse(account, rule))
	default:
		http.Error(w, "", http.StatusNotFound)
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
