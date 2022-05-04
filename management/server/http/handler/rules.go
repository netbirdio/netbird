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

// Rules is a handler that returns rules of the account
type Rules struct {
	accountManager server.AccountManager
	authAudience   string
	jwtExtractor   jwtclaims.ClaimsExtractor
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

	writeJSONObject(w, account.Rules)
}

func (h *Rules) CreateOrUpdateRuleHandler(w http.ResponseWriter, r *http.Request) {
	account, err := h.getRuleAccount(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var req server.Rule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		req.ID = xid.New().String()
	}

	if err := h.accountManager.SaveRule(account.Id, &req); err != nil {
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

		writeJSONObject(w, rule)
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
