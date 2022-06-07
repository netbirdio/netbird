package handler

import (
	"encoding/json"
	"fmt"
	"github.com/netbirdio/netbird/management/server/http/api"
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/rs/xid"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const FlowBidirectString = "bidirect"

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
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	rules := []*api.Rule{}
	for _, r := range account.Rules {
		rules = append(rules, toRuleResponse(account, r))
	}

	writeJSONObject(w, rules)
}

// UpdateRuleHandler handles update to a rule identified by a given ID
func (h *Rules) UpdateRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
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

	var reqSources []string
	if req.Source != nil {
		reqSources = *req.Source
	}

	var reqDestinations []string
	if req.Destination != nil {
		reqDestinations = *req.Destination
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
	case FlowBidirectString:
		rule.Flow = server.TrafficFlowBidirect
	default:
		http.Error(w, "unknown flow type", http.StatusBadRequest)
		return
	}

	if err := h.accountManager.SaveRule(account.Id, &rule); err != nil {
		log.Errorf("failed updating rule \"%s\" under account %s %v", req.Name, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, &req)
}

// CreateRuleHandler handles rule creation request
func (h *Rules) CreateRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var req api.PostApiRulesJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var reqSources []string
	if req.Source != nil {
		reqSources = *req.Source
	}

	var reqDestinations []string
	if req.Destination != nil {
		reqDestinations = *req.Destination
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
	case FlowBidirectString:
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

	writeJSONObject(w, &req)
}

// DeleteRuleHandler handles rule deletion request
func (h *Rules) DeleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
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

	writeJSONObject(w, "")
}

// GetRuleHandler handles a group Get request identified by ID
func (h *Rules) GetRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
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

		rule, err := h.accountManager.GetRule(account.Id, ruleID)
		if err != nil {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}

		writeJSONObject(w, toRuleResponse(account, rule))
	default:
		http.Error(w, "", http.StatusNotFound)
	}
}

func toRuleResponse(account *server.Account, rule *server.Rule) *api.Rule {
	gr := api.Rule{
		ID:   rule.ID,
		Name: rule.Name,
	}

	switch rule.Flow {
	case server.TrafficFlowBidirect:
		gr.Flow = FlowBidirectString
	default:
		gr.Flow = "unknown"
	}

	for _, gid := range rule.Source {
		if group, ok := account.Groups[gid]; ok {
			gr.Source = append(gr.Source, api.GroupMinimum{
				ID:         group.ID,
				Name:       group.Name,
				PeersCount: len(group.Peers),
			})
		}
	}

	for _, gid := range rule.Destination {
		if group, ok := account.Groups[gid]; ok {
			gr.Destination = append(gr.Destination, api.GroupMinimum{
				ID:         group.ID,
				Name:       group.Name,
				PeersCount: len(group.Peers),
			})
		}
	}

	return &gr
}
