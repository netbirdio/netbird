package uspfilter

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/internal/wincmd"
)

type action string

const (
	addRule    action = "add"
	deleteRule action = "delete"
)

// WindowsInterfaceAllower opens the NetBird interface in the Windows firewall
// via netsh advfirewall rules. It implements InterfaceAllower for the userspace
// firewall on Windows.
type WindowsInterfaceAllower struct {
	iface Iface
}

// NewWindowsInterfaceAllower builds the Windows netsh-based interface allower.
func NewWindowsInterfaceAllower(iface Iface) *WindowsInterfaceAllower {
	return &WindowsInterfaceAllower{iface: iface}
}

// Apply adds inbound-allow netsh rules for the interface's addresses.
func (a *WindowsInterfaceAllower) Apply() error {
	if !isWindowsFirewallReachable() {
		return nil
	}

	inst := instance.Current()
	ruleName, ruleNameV6 := inst.FirewallRuleName(), inst.FirewallRuleNameV6()

	if !inst.IsDefault() {
		removeStaleRules(ruleName, ruleNameV6)
	}

	if !isFirewallRuleActive(ruleName) {
		if err := manageFirewallRule(ruleName,
			addRule,
			"dir=in",
			"enable=yes",
			"action=allow",
			"profile=any",
			"localip="+a.iface.Address().IP.String(),
		); err != nil {
			return err
		}
	}

	if v6 := a.iface.Address().IPv6; v6.IsValid() && !isFirewallRuleActive(ruleNameV6) {
		if err := manageFirewallRule(ruleNameV6,
			addRule,
			"dir=in",
			"enable=yes",
			"action=allow",
			"profile=any",
			"localip="+v6.String(),
		); err != nil {
			return err
		}
	}

	return nil
}

// Close removes the netsh rules added by Apply.
func (a *WindowsInterfaceAllower) Close() error {
	if !isWindowsFirewallReachable() {
		return nil
	}

	inst := instance.Current()
	ruleName, ruleNameV6 := inst.FirewallRuleName(), inst.FirewallRuleNameV6()

	var merr *multierror.Error
	if isFirewallRuleActive(ruleName) {
		if err := manageFirewallRule(ruleName, deleteRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove windows firewall rule: %w", err))
		}
	}
	if isFirewallRuleActive(ruleNameV6) {
		if err := manageFirewallRule(ruleNameV6, deleteRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove windows v6 firewall rule: %w", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// removeStaleRules deletes rules left by an earlier run of a named installation.
// The rules have no crash state, so after a crash and an address change a reused
// rule would allow the old overlay address and keep blocking the new one;
// recreating them is simpler than parsing netsh's localized output.
func removeStaleRules(names ...string) {
	for _, name := range names {
		if !isFirewallRuleActive(name) {
			continue
		}
		if err := manageFirewallRule(name, deleteRule); err != nil {
			log.Warnf("remove stale windows firewall rule %s: %v", name, err)
		}
	}
}

func manageFirewallRule(ruleName string, action action, extraArgs ...string) error {
	args := []string{"advfirewall", "firewall", string(action), "rule", "name=" + ruleName}
	if action == addRule {
		args = append(args, extraArgs...)
	}
	netshCmd := wincmd.System32("netsh")
	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func isWindowsFirewallReachable() bool {
	args := []string{"advfirewall", "show", "allprofiles", "state"}

	netshCmd := wincmd.System32("netsh")

	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	_, err := cmd.Output()
	if err != nil {
		log.Infof("Windows firewall is not reachable, skipping default rule management. Using only user space rules. Error: %s", err)
		return false
	}

	return true
}

func isFirewallRuleActive(ruleName string) bool {
	args := []string{"advfirewall", "firewall", "show", "rule", "name=" + ruleName}

	netshCmd := wincmd.System32("netsh")

	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err := cmd.Output()
	return err == nil
}
