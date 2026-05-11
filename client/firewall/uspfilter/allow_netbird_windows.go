package uspfilter

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

type action string

const (
	addRule          action = "add"
	deleteRule       action = "delete"
	firewallRuleName        = "Netbird"
)

// Close cleans up the firewall manager by removing all rules and closing trackers
func (m *Manager) Close(*statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.resetState()

	if !isWindowsFirewallReachable() {
		return nil
	}

	var merr *multierror.Error
	if isFirewallRuleActive(firewallRuleName) {
		if err := manageFirewallRule(firewallRuleName, deleteRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove windows firewall rule: %w", err))
		}
	}

	if isFirewallRuleActive(firewallRuleName + "-v6") {
		if err := manageFirewallRule(firewallRuleName+"-v6", deleteRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove windows v6 firewall rule: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if !isWindowsFirewallReachable() {
		return nil
	}

	if !isFirewallRuleActive(firewallRuleName) {
		if err := manageFirewallRule(firewallRuleName,
			addRule,
			"dir=in",
			"enable=yes",
			"action=allow",
			"profile=any",
			"localip="+m.wgIface.Address().IP.String(),
		); err != nil {
			return err
		}
	}

	if v6 := m.wgIface.Address().IPv6; v6.IsValid() && !isFirewallRuleActive(firewallRuleName+"-v6") {
		if err := manageFirewallRule(firewallRuleName+"-v6",
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

func manageFirewallRule(ruleName string, action action, extraArgs ...string) error {

	args := []string{"advfirewall", "firewall", string(action), "rule", "name=" + ruleName}
	if action == addRule {
		args = append(args, extraArgs...)
	}
	netshCmd := GetSystem32Command("netsh")
	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func isWindowsFirewallReachable() bool {
	args := []string{"advfirewall", "show", "allprofiles", "state"}

	netshCmd := GetSystem32Command("netsh")

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

	netshCmd := GetSystem32Command("netsh")

	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err := cmd.Output()
	return err == nil
}

// GetSystem32Command checks if a command can be found in the system path and returns it. In case it can't find it
// in the path it will return the full path of a command assuming C:\windows\system32 as the base path.
func GetSystem32Command(command string) string {
	_, err := exec.LookPath(command)
	if err == nil {
		return command
	}

	log.Tracef("Command %s not found in PATH, using C:\\windows\\system32\\%s.exe path", command, command)

	return "C:\\windows\\system32\\" + command + ".exe"
}
