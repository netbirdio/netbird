package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/require"
)

func TestRulesetManager_createRuleset(t *testing.T) {
	// Create a ruleset manager.
	rulesetManager := newRuleManager()

	// Create a ruleset.
	rulesetID := "ruleset-1"
	nftRule := nftables.Rule{
		UserData: []byte(rulesetID),
	}
	ruleset := rulesetManager.createRuleset(rulesetID, &nftRule, nil)
	require.NotNil(t, ruleset, "createRuleset() failed")
	require.Equal(t, ruleset.rulesetID, rulesetID, "rulesetID is incorrect")
	require.Equal(t, ruleset.nftRule, &nftRule, "nftRule is incorrect")
}

func TestRulesetManager_addRule(t *testing.T) {
	// Create a ruleset manager.
	rulesetManager := newRuleManager()

	// Create a ruleset.
	rulesetID := "ruleset-1"
	nftRule := nftables.Rule{}
	ruleset := rulesetManager.createRuleset(rulesetID, &nftRule, nil)

	// Add a rule to the ruleset.
	ip := []byte("192.168.1.1")
	rule, err := rulesetManager.addRule(ruleset, ip)
	require.NoError(t, err, "addRule() failed")
	require.NotNil(t, rule, "rule should not be nil")
	require.NotEqual(t, rule.ruleID, "ruleID is empty")
	require.EqualValues(t, rule.ip, ip, "ip is incorrect")
	require.Contains(t, ruleset.issuedRules, rule.ruleID, "ruleID already exists in ruleset")
	require.Contains(t, rulesetManager.issuedRuleID2rulesetID, rule.ruleID, "ruleID already exists in ruleset manager")

	ruleset2 := &nftRuleset{
		rulesetID: "ruleset-2",
	}
	_, err = rulesetManager.addRule(ruleset2, ip)
	require.Error(t, err, "addRule() should have failed")
}

func TestRulesetManager_deleteRule(t *testing.T) {
	// Create a ruleset manager.
	rulesetManager := newRuleManager()

	// Create a ruleset.
	rulesetID := "ruleset-1"
	nftRule := nftables.Rule{}
	ruleset := rulesetManager.createRuleset(rulesetID, &nftRule, nil)

	// Add a rule to the ruleset.
	ip := []byte("192.168.1.1")
	rule, err := rulesetManager.addRule(ruleset, ip)
	require.NoError(t, err, "addRule() failed")
	require.NotNil(t, rule, "rule should not be nil")

	ip2 := []byte("192.168.1.1")
	rule2, err := rulesetManager.addRule(ruleset, ip2)
	require.NoError(t, err, "addRule() failed")
	require.NotNil(t, rule2, "rule should not be nil")

	hasNext := rulesetManager.deleteRule(rule)
	require.True(t, hasNext, "deleteRule() should have returned true")

	// Check that the rule is no longer in the manager.
	require.NotContains(t, rulesetManager.issuedRuleID2rulesetID, rule.ruleID, "rule should have been deleted")

	hasNext = rulesetManager.deleteRule(rule2)
	require.False(t, hasNext, "deleteRule() should have returned false")
}

func TestRulesetManager_setNftRuleHandle(t *testing.T) {
	// Create a ruleset manager.
	rulesetManager := newRuleManager()
	// Create a ruleset.
	rulesetID := "ruleset-1"
	nftRule := nftables.Rule{}
	ruleset := rulesetManager.createRuleset(rulesetID, &nftRule, nil)
	// Add a rule to the ruleset.
	ip := []byte("192.168.0.1")

	rule, err := rulesetManager.addRule(ruleset, ip)
	require.NoError(t, err, "addRule() failed")
	require.NotNil(t, rule, "rule should not be nil")

	nftRuleCopy := nftRule
	nftRuleCopy.Handle = 2
	nftRuleCopy.UserData = []byte(rulesetID)
	err = rulesetManager.setNftRuleHandle(&nftRuleCopy)
	require.NoError(t, err, "setNftRuleHandle() failed")
	// check correct work with references
	require.Equal(t, nftRule.Handle, uint64(2), "nftRule.Handle is incorrect")
}

func TestRulesetManager_getRuleset(t *testing.T) {
	// Create a ruleset manager.
	rulesetManager := newRuleManager()
	// Create a ruleset.
	rulesetID := "ruleset-1"
	nftRule := nftables.Rule{}
	nftSet := nftables.Set{
		ID: 2,
	}
	ruleset := rulesetManager.createRuleset(rulesetID, &nftRule, &nftSet)
	require.NotNil(t, ruleset, "createRuleset() failed")

	find, ok := rulesetManager.getRuleset(rulesetID)
	require.True(t, ok, "getRuleset() failed")
	require.Equal(t, ruleset, find, "getRulesetBySetID() failed")

	_, ok = rulesetManager.getRuleset("does-not-exist")
	require.False(t, ok, "getRuleset() failed")
}
