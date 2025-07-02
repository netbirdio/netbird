package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestParseBoolArg(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
		hasError bool
	}{
		{"true", true, false},
		{"True", true, false},
		{"1", true, false},
		{"yes", true, false},
		{"on", true, false},
		{"false", false, false},
		{"False", false, false},
		{"0", false, false},
		{"no", false, false},
		{"off", false, false},
		{"invalid", false, true},
		{"maybe", false, true},
		{"", false, true},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := parseBoolArg(test.input)
			
			if test.hasError {
				if err == nil {
					t.Errorf("Expected error for input %q, but got none", test.input)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input %q: %v", test.input, err)
				}
				if result != test.expected {
					t.Errorf("For input %q, expected %v but got %v", test.input, test.expected, result)
				}
			}
		})
	}
}

func TestSetCommandStructure(t *testing.T) {
	// Test that the set command has the expected subcommands
	expectedSubcommands := []string{
		"autoconnect",
		"ssh-server", 
		"network-monitor",
		"rosenpass",
		"dns",
		"dns-interval",
	}

	actualSubcommands := make([]string, 0, len(setCmd.Commands()))
	for _, cmd := range setCmd.Commands() {
		actualSubcommands = append(actualSubcommands, cmd.Name())
	}

	if len(actualSubcommands) != len(expectedSubcommands) {
		t.Errorf("Expected %d subcommands, got %d", len(expectedSubcommands), len(actualSubcommands))
	}

	for _, expected := range expectedSubcommands {
		found := false
		for _, actual := range actualSubcommands {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subcommand %q not found", expected)
		}
	}
}

func TestSetCommandUsage(t *testing.T) {
	if setCmd.Use != "set" {
		t.Errorf("Expected command use to be 'set', got %q", setCmd.Use)
	}

	if setCmd.Short != "Set NetBird client configuration" {
		t.Errorf("Expected short description to be 'Set NetBird client configuration', got %q", setCmd.Short)
	}
}

func TestSubcommandArgRequirements(t *testing.T) {
	// Test that all subcommands except dns-interval require exactly 1 argument
	subcommands := []*cobra.Command{
		setAutoconnectCmd,
		setSSHServerCmd,
		setNetworkMonitorCmd,
		setRosenpassCmd,
		setDNSCmd,
		setDNSIntervalCmd,
	}

	for _, cmd := range subcommands {
		if cmd.Args == nil {
			t.Errorf("Command %q should have Args validation", cmd.Name())
		}
	}
}