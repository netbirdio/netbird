package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/rs/xid"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const FlowBidirectString = "bidirect"

// RuleResponse is a response sent to the client
type RuleResponse struct {
	ID          string
	Name        string
	Source      []RuleGroupResponse
	Destination []RuleGroupResponse
	Flow        string
}

// RuleGroupResponse is a response sent to the client
type RuleGroupResponse struct {
	ID         string
	Name       string
	PeersCount int
}

// RuleRequest to create or update rule
type RuleRequest struct {
	ID          string
	Name        string
	Source      []string
	Destination []string
	Flow        string
}

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
	account, err := h.getRuleAccount(r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var rules []*RuleResponse
	for _, r := range account.Rules {
		rules = append(rules, toRuleResponse(account, r))
	}

	writeJSONObject(w, rules)
}

func (h *Rules) CreateOrUpdateRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := h.getRuleAccount(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		req.ID = xid.New().String()
	}

	rule := server.Rule{
		ID:          req.ID,
		Name:        req.Name,
		Source:      req.Source,
		Destination: req.Destination,
	}

	switch req.Flow {
	case FlowBidirectString:
		rule.Flow = server.TrafficFlowBidirect
	default:
		http.Error(w, "unknown flow type", http.StatusBadRequest)
		return
	}

	if err := h.accountManager.SaveRule(account.Id, &rule); err != nil {
		log.Errorf("failed updating rule %s under account %s %v", req.ID, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, &req)
}

func (h *Rules) DeleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := h.getRuleAccount(r)
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

func (h *Rules) GetRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := h.getRuleAccount(r)
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

func (h *Rules) getRuleAccount(r *http.Request) (*server.Account, error) {
	jwtClaims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)

	account, err := h.accountManager.GetAccountWithAuthorizationClaims(jwtClaims)
	if err != nil {
		return nil, fmt.Errorf("failed getting account of a user %s: %v", jwtClaims.UserId, err)
	}

	return account, nil
}

func toRuleResponse(account *server.Account, rule *server.Rule) *RuleResponse {
	gr := RuleResponse{
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
			gr.Source = append(gr.Source, RuleGroupResponse{
				ID:         group.ID,
				Name:       group.Name,
				PeersCount: len(group.Peers),
			})
		}
	}

	for _, gid := range rule.Destination {
		if group, ok := account.Groups[gid]; ok {
			gr.Destination = append(gr.Destination, RuleGroupResponse{
				ID:         group.ID,
				Name:       group.Name,
				PeersCount: len(group.Peers),
			})
		}
	}

	return &gr
}
