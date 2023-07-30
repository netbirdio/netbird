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
	rulesets map[string]*nftRuleset

	nftSetName2rulesetID   map[string]string
	issuedRuleID2rulesetID map[string]string
}

func newRuleManager() *rulesetManager {
	return &rulesetManager{
		rulesets: map[string]*nftRuleset{},

		nftSetName2rulesetID:   map[string]string{},
		issuedRuleID2rulesetID: map[string]string{},
	}
}

func (r *rulesetManager) getRuleset(rulesetID string) (*nftRuleset, bool) {
	ruleset, ok := r.rulesets[rulesetID]
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
		r.nftSetName2rulesetID[nftSet.Name] = ruleset.rulesetID
	}
	return &ruleset
}

func (r *rulesetManager) addRule(
	ruleset *nftRuleset,
	ip []byte,
) (*Rule, error) {
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
			delete(r.nftSetName2rulesetID, rule.nftSet.Name)
		}
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
		return fmt.Errorf("ruleset not found")
	}
	*ruleset.nftRule = *nftRule
	return nil
}
