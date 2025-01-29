package ingressgw

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

type DNATFirewall interface {
	AddDNATRule(fwdRule firewall.ForwardRule) (firewall.Rule, error)
	DeleteDNATRule(rule firewall.Rule) error
}

type RulePair struct {
	firewall.ForwardRule
	firewall.Rule
}

type Manager struct {
	dnatFirewall DNATFirewall

	rules   map[string]RulePair // keys is the ID of the ForwardRule
	rulesMu sync.Mutex
}

func NewManager(dnatFirewall DNATFirewall) *Manager {
	return &Manager{
		dnatFirewall: dnatFirewall,
		rules:        make(map[string]RulePair),
	}
}

func (h *Manager) Update(forwardRules []firewall.ForwardRule) error {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()

	var mErr *multierror.Error

	toDelete := make(map[string]RulePair, len(h.rules))
	for id, r := range h.rules {
		toDelete[id] = r
	}

	// Process new/updated rules
	for _, fwdRule := range forwardRules {
		id := fwdRule.ID()
		if _, ok := h.rules[id]; ok {
			delete(toDelete, id)
			continue
		}

		rule, err := h.dnatFirewall.AddDNATRule(fwdRule)
		if err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("add forward rule '%s': %v", fwdRule.String(), err))
			continue
		}
		log.Infof("forward rule has been added '%s'", fwdRule)
		h.rules[id] = RulePair{
			ForwardRule: fwdRule,
			Rule:        rule,
		}
	}

	// Remove deleted rules
	for id, rulePair := range toDelete {
		if err := h.dnatFirewall.DeleteDNATRule(rulePair.Rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete forward rule '%s': %v", rulePair.ForwardRule.String(), err))
		}
		log.Infof("forward rule has been deleted '%s'", rulePair.ForwardRule)
		delete(h.rules, id)
	}

	return nberrors.FormatErrorOrNil(mErr)
}

func (h *Manager) Close() error {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()

	log.Infof("clean up all (%d) forward rules", len(h.rules))
	var mErr *multierror.Error
	for _, rule := range h.rules {
		if err := h.dnatFirewall.DeleteDNATRule(rule.Rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete forward rule '%s': %v", rule, err))
		}
	}

	h.rules = make(map[string]RulePair)
	return nberrors.FormatErrorOrNil(mErr)
}

func (h *Manager) Rules() []firewall.ForwardRule {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()

	rules := make([]firewall.ForwardRule, 0, len(h.rules))
	for _, rulePair := range h.rules {
		rules = append(rules, rulePair.ForwardRule)
	}

	return rules
}
