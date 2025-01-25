package ingressgw

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall/interface"
	"github.com/netbirdio/netbird/client/firewall/types"
)

type RulePair struct {
	types.ForwardRule
	types.Rule
}

type Manager struct {
	firewall _interface.Firewall

	rules   map[string]RulePair // keys is the ID of the ForwardRule
	rulesMu sync.Mutex
}

func NewManager(firewall _interface.Firewall) *Manager {
	return &Manager{
		firewall: firewall,
		rules:    make(map[string]RulePair),
	}
}

func (h *Manager) Update(forwardRules []types.ForwardRule) error {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()

	var mErr *multierror.Error
	toDelete := make(map[string]RulePair)
	for id, r := range h.rules {
		toDelete[id] = r
	}

	// Process new/updated rules
	for _, fwdRule := range forwardRules {
		id := fwdRule.GetRuleID()
		if _, ok := h.rules[id]; ok {
			delete(toDelete, id)
			continue
		}

		rule, err := h.firewall.AddDNATRule(fwdRule)
		if err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to add forward rule '%s': %v", fwdRule.String(), err))
			continue
		}
		log.Infof("added forward rule '%s'", fwdRule)
		h.rules[id] = RulePair{
			ForwardRule: fwdRule,
			Rule:        rule,
		}
	}

	// Remove deleted rules
	for id, rulePair := range toDelete {
		if err := h.firewall.DeleteDNATRule(rulePair.Rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete forward rule '%s': %v", rulePair.ForwardRule.String(), err))
		}
		delete(h.rules, id)
	}

	return nberrors.FormatErrorOrNil(mErr)
}

func (h *Manager) Close() error {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()

	log.Infof("clean up all forward rules (%d)", len(h.rules))
	var mErr *multierror.Error
	for _, rule := range h.rules {
		if err := h.firewall.DeleteDNATRule(rule.Rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete forward rule '%s': %v", rule, err))
		}
	}
	return nberrors.FormatErrorOrNil(mErr)
}

func (h *Manager) Rules() []types.ForwardRule {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()

	rules := make([]types.ForwardRule, 0, len(h.rules))
	for _, rulePair := range h.rules {
		rules = append(rules, rulePair.ForwardRule)
	}

	return rules
}
