package uspfilter

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

type action string

const (
	addRule          action = "add"
	deleteRule       action = "delete"
	firewallRuleName        = "Netbird"
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

	if !isFirewallRuleActive(firewallRuleName) {
		if err := manageFirewallRule(firewallRuleName,
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

	if v6 := a.iface.Address().IPv6; v6.IsValid() && !isFirewallRuleActive(firewallRuleName+"-v6") {
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

// Close removes the netsh rules added by Apply.
func (a *WindowsInterfaceAllower) Close() error {
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
