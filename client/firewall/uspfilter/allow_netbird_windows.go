package uspfilter

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
)

type action string

const (
	addRule    action = "add"
	deleteRule action = "delete"

	firewallRuleName     = "Netbird"
	noRulesMatchCriteria = "No rules match the specified criteria"
)

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	return manageFirewallRule(firewallRuleName,
		addRule,
		"dir=in",
		"enable=yes",
		"action=allow",
		"profile=any",
		"localip="+m.wgIface.Address().IP.String(),
	)
}

func manageFirewallRule(ruleName string, action action, args ...string) error {
	active, err := isFirewallRuleActive(ruleName)
	if err != nil {
		return err
	}

	if (action == addRule && !active) || (action == deleteRule && active) {
		baseArgs := []string{"advfirewall", "firewall", string(action), "rule", "name=" + ruleName}
		args := append(baseArgs, args...)

		cmd := exec.Command("netsh", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	}

	return nil
}

func isFirewallRuleActive(ruleName string) (bool, error) {
	args := []string{"advfirewall", "firewall", "show", "rule", "name=" + ruleName}

	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			// if the firewall rule is not active, we expect last exit code to be 1
			exitStatus := exitError.Sys().(syscall.WaitStatus).ExitStatus()
			if exitStatus == 1 {
				if strings.Contains(string(output), noRulesMatchCriteria) {
					return false, nil
				}
			}
		}
		return false, err
	}

	if strings.Contains(string(output), noRulesMatchCriteria) {
		return false, nil
	}

	return true, nil
}
