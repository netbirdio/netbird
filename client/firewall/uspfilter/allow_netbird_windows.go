package uspfilter

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
)

const noRulesMatchCriteria = "No rules match the specified criteria"

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	return addFirewallRule("Netbird",
		"dir=in",
		"enable=yes",
		"action=allow",
		"profile=any",
		"localip="+m.wgIface.Address().IP.String(),
	)
}

func addFirewallRule(ruleName string, args ...string) error {
	active, err := isFirewallRuleActive(ruleName)
	if err != nil {
		return err
	}

	if !active {
		baseArgs := []string{"advfirewall", "firewall", "add", "rule", "name=" + ruleName}
		args = append(baseArgs, args...)

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
			// if firewall rule is not active, we expect last exit code to be 1
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
