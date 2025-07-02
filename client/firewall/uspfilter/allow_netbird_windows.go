package uspfilter

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// allowNetBirdFirewall adds a Windows firewall rule to allow NetBird traffic
func allowNetBirdFirewall() error {
	// Use secure command execution with validated parameters
	return executeSecureFirewallCommand("add", "NetBird", "UDP", "51820")
}

// validateInput validates firewall rule parameters to prevent injection
func validateInput(input, inputType string) error {
	switch inputType {
	case "ruleName":
		// Allow only alphanumeric characters, spaces, hyphens, and underscores
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9\s\-_]+$`, input); !matched {
			return fmt.Errorf("invalid rule name: contains unsafe characters")
		}
		if len(input) > 255 {
			return fmt.Errorf("rule name too long")
		}
	case "protocol":
		protocol := strings.ToUpper(input)
		if protocol != "TCP" && protocol != "UDP" {
			return fmt.Errorf("invalid protocol: must be TCP or UDP")
		}
	case "port":
		if matched, _ := regexp.MatchString(`^[0-9]+$`, input); !matched {
			return fmt.Errorf("invalid port: must be numeric")
		}
	case "action":
		action := strings.ToLower(input)
		if action != "add" && action != "delete" {
			return fmt.Errorf("invalid action: must be add or delete")
		}
	default:
		return fmt.Errorf("unknown input type")
	}
	return nil
}

// executeSecureFirewallCommand safely executes firewall commands with validation
func executeSecureFirewallCommand(action, ruleName, protocol, port string) error {
	// Validate all inputs
	if err := validateInput(action, "action"); err != nil {
		return err
	}
	if err := validateInput(ruleName, "ruleName"); err != nil {
		return err
	}
	if err := validateInput(protocol, "protocol"); err != nil {
		return err
	}
	if err := validateInput(port, "port"); err != nil {
		return err
	}

	// Build command arguments safely - no string concatenation or interpolation
	args := []string{"advfirewall", "firewall", action, "rule", "name=" + ruleName}
	if action == "add" {
		args = append(args, "protocol="+strings.ToUpper(protocol), "localport="+port, "action=allow")
	}
	
	return exec.Command("netsh", args...).Run()
}
