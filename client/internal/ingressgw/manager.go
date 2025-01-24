package ingressgw

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
)

type Manager struct {
	firewallManager firewallManager.Manager

	fwRules map[string]firewallManager.Rule
}

func NewManager(firewall firewallManager.Manager) *Manager {
	return &Manager{
		firewallManager: firewall,
		fwRules:         make(map[string]firewallManager.Rule),
	}
}

func (h *Manager) Update(forwardRules []firewallManager.ForwardRule) error {
	var mErr *multierror.Error
	toDelete := make(map[string]firewallManager.Rule)
	for id, r := range h.fwRules {
		toDelete[id] = r
	}

	// Process new/updated rules
	for _, rule := range forwardRules {
		id := rule.GetRuleID()
		if _, ok := h.fwRules[id]; ok {
			delete(toDelete, id)
			continue
		}

		rule, err := h.firewallManager.AddDNATRule(rule)
		if err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to add forward rule '%s': %v", rule, err))
		}
		h.fwRules[id] = rule
	}

	// Remove deleted rules
	for id, rule := range toDelete {
		if err := h.firewallManager.DeleteDNATRule(rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete forward rule '%s': %v", rule, err))
		}
		delete(h.fwRules, id)
	}
	return nberrors.FormatErrorOrNil(mErr)
}

func (h *Manager) Close() error {
	var mErr *multierror.Error
	for _, rule := range h.fwRules {
		if err := h.firewallManager.DeleteDNATRule(rule); err != nil {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete forward rule '%s': %v", rule, err))
		}
	}
	return nberrors.FormatErrorOrNil(mErr)
}
