package nftables

import (
	"bytes"
	"fmt"

	"github.com/google/nftables"
	"github.com/rs/xid"
)

// nftRuleset links native firewall rule and ipset to ACL generated rules
type nftRuleset struct {
	nftRule     *nftables.Rule
	nftSet      *nftables.Set
	issuedRules map[string]*Rule
	rulesetID   string
}

type rulesetManager struct {
	rulesets               map[string]*nftRuleset
	issuedRuleID2rulesetID map[string]string
}

func newRuleManager() *rulesetManager {
	return &rulesetManager{
		rulesets:               map[string]*nftRuleset{},
		issuedRuleID2rulesetID: map[string]string{},
	}
}

func (r *rulesetManager) isRulesetExists(rulesetID string) bool {
	_, ok := r.rulesets[rulesetID]
	return ok
}

func (r *rulesetManager) createRuleset(rulesetID string, nftRule *nftables.Rule, nftSet *nftables.Set) {
	ruleset := nftRuleset{
		rulesetID:   rulesetID,
		nftRule:     nftRule,
		nftSet:      nftSet,
		issuedRules: map[string]*Rule{},
	}
	r.rulesets[rulesetID] = &ruleset
	return
}

func (r *rulesetManager) addRule(rulesetID string, ip []byte) (*Rule, error) {
	ruleset, ok := r.rulesets[rulesetID]
	if !ok {
		return nil, fmt.Errorf("ruleset not found")
	}

	rule := Rule{
		nftRule: ruleset.nftRule,
		nftSet:  ruleset.nftSet,
		ruleID:  xid.New().String(),
		ip:      ip,
	}

	ruleset.issuedRules[rule.ruleID] = &rule
	r.issuedRuleID2rulesetID[rule.ruleID] = rulesetID

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
		return false
	}
	return true
}

// setNftRuleHandle finds rule by userdata which contains rulesetID and updates it's handle number
//
// This is important to do, because after we add rule to the nftables we can't update it until
// we set correct handle value to it.
func (r *rulesetManager) setNftRuleHandle(nftRule *nftables.Rule) error {
	split := bytes.Split(nftRule.UserData, []byte(" "))
	ruleset, ok := r.rulesets[string(split[0])]
	if !ok {
		return fmt.Errorf("ruleset not found: %s", string(split[0]))
	}
	*ruleset.nftRule = *nftRule
	return nil
}
