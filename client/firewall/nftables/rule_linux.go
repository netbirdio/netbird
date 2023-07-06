package nftables

import (
	"bytes"
	"fmt"

	"github.com/google/nftables"
	"github.com/rs/xid"
)

// Rule to handle management of rules
type Rule struct {
	nftRule *nftables.Rule
	nftSet  *nftables.Set

	ruleID string
	ip     []byte
}

// GetRuleID returns the rule id
func (r *Rule) GetRuleID() string {
	return r.ruleID
}

type nftRuleset struct {
	nftRule     *nftables.Rule
	nftSet      *nftables.Set
	issuedRules map[string]*Rule
	rulesetID   string
}

type rulesetManager struct {
	rulesets map[string]*nftRuleset

	nftSetID2rulesetID     map[uint32]string
	issuedRuleID2rulesetID map[string]string
}

func newRuleManager() *rulesetManager {
	return &rulesetManager{
		rulesets: map[string]*nftRuleset{},

		nftSetID2rulesetID:     map[uint32]string{},
		issuedRuleID2rulesetID: map[string]string{},
	}
}

func (r *rulesetManager) getRulesetBySetID(nftIpsetID uint32) (*nftRuleset, bool) {
	ruleset, ok := r.rulesets[r.nftSetID2rulesetID[nftIpsetID]]
	return ruleset, ok
}

func (r *rulesetManager) createRuleset(
	rulesetID string,
	nftRule *nftables.Rule,
	nftSet *nftables.Set,
) *nftRuleset {
	ruleset := nftRuleset{
		rulesetID:   rulesetID,
		nftRule:     nftRule,
		nftSet:      nftSet,
		issuedRules: map[string]*Rule{},
	}
	r.rulesets[ruleset.rulesetID] = &ruleset
	if nftSet != nil {
		r.nftSetID2rulesetID[nftSet.ID] = ruleset.rulesetID
	}
	return &ruleset
}

func (r *rulesetManager) addRule(ruleset *nftRuleset, ip []byte) (*Rule, error) {
	if _, ok := r.rulesets[ruleset.rulesetID]; !ok {
		return nil, fmt.Errorf("ruleset not found")
	}

	rule := Rule{
		nftRule: ruleset.nftRule,
		nftSet:  ruleset.nftSet,
		ruleID:  xid.New().String(),
		ip:      ip,
	}

	ruleset.issuedRules[rule.ruleID] = &rule
	r.issuedRuleID2rulesetID[rule.ruleID] = ruleset.rulesetID

	return &rule, nil
}

// deleteRule from ruleset and returns true if contains other rules
func (r *rulesetManager) deleteRule(rule *Rule) bool {
	rulesetID, ok := r.issuedRuleID2rulesetID[rule.ruleID]
	if !ok {
		return false
	}

	ruleset := r.rulesets[rulesetID]
	if ruleset.nftRule == nil {
		return false
	}
	delete(r.issuedRuleID2rulesetID, rule.ruleID)
	delete(ruleset.issuedRules, rule.ruleID)

	if len(ruleset.issuedRules) == 0 {
		delete(r.rulesets, ruleset.rulesetID)
		if rule.nftSet != nil {
			delete(r.nftSetID2rulesetID, ruleset.nftSet.ID)
		}
		return false
	}
	return true
}

func (r *rulesetManager) setNftRuleHandle(nftRule *nftables.Rule) error {
	split := bytes.Split(nftRule.UserData, []byte(" "))
	rulesetID := string(split[0])
	ruleset, ok := r.rulesets[rulesetID]
	if !ok {
		return fmt.Errorf("ruleset not found")
	}
	*ruleset.nftRule = *nftRule
	return nil
}
