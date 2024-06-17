package uspfilter

import (
	"fmt"
	"os/exec"
	"syscall"

	log "github.com/sirupsen/logrus"
)

type action string

const (
	addRule          action = "add"
	deleteRule       action = "delete"
	firewallRuleName        = "Netbird"
)

// Reset firewall to the default state
func (m *Manager) Reset() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.outgoingRules = make(map[string]RuleSet)
	m.incomingRules = make(map[string]RuleSet)

	if !isWindowsFirewallReachable() {
		return nil
	}

	if !isFirewallRuleActive(firewallRuleName) {
		return nil
	}

	if err := manageFirewallRule(firewallRuleName, deleteRule); err != nil {
		return fmt.Errorf("couldn't remove windows firewall: %w", err)
	}

	return nil
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if !isWindowsFirewallReachable() {
		return nil
	}

	if isFirewallRuleActive(firewallRuleName) {
		return nil
	}
	return manageFirewallRule(firewallRuleName,
		addRule,
		"dir=in",
		"enable=yes",
		"action=allow",
		"profile=any",
		"localip="+m.wgIface.Address().IP.String(),
	)
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
