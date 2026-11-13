package cmd

import (
	"fmt"
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
)

func TestInitCommands(t *testing.T) {
	helpFlag := "-h"
	commandArgs := [][]string{{"root", helpFlag}}
	for _, command := range rootCmd.Commands() {
		commandArgs = append(commandArgs, []string{command.Name(), command.Name(), helpFlag})
		for _, subcommand := range command.Commands() {
			commandArgs = append(commandArgs, []string{command.Name() + " " + subcommand.Name(), command.Name(), subcommand.Name(), helpFlag})
		}
	}

	for _, args := range commandArgs {
		t.Run(fmt.Sprintf("Testing Command %s", args[0]), func(t *testing.T) {
			defer func() {
				err := recover()
				if err != nil {
					t.Fatalf("got an panic error while running the command: %s -h. Error: %s", args[0], err)
				}
			}()

			rootCmd.SetArgs(args[1:])
			rootCmd.SetOut(io.Discard)
			if err := rootCmd.Execute(); err != nil {
				t.Errorf("expected no error while running %s command, got %v", args[0], err)
				return
			}
		})
	}
}

func TestSetFlagsFromEnvVars(t *testing.T) {
	var cmd = &cobra.Command{
		Use:          "netbird",
		Long:         "test",
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			SetFlagsFromEnvVars(cmd)
		},
	}

	cmd.PersistentFlags().StringSliceVar(&natExternalIPs, externalIPMapFlag, nil,
		`comma separated list of external IPs to map to the WireGuard interface`)
	cmd.PersistentFlags().StringVar(&interfaceName, interfaceNameFlag, iface.WgInterfaceDefault, "WireGuard interface name")
	cmd.PersistentFlags().BoolVar(&rosenpassEnabled, enableRosenpassFlag, false, "Enable Rosenpass feature Rosenpass.")
	cmd.PersistentFlags().Uint16Var(&wireguardPort, wireguardPortFlag, iface.DefaultWgPort, "WireGuard interface listening port")
	cmd.PersistentFlags().Uint16Var(&mtu, mtuFlag, iface.DefaultMTU, "Set MTU (Maximum Transmission Unit) for the WireGuard interface")

	t.Setenv("NB_EXTERNAL_IP_MAP", "abc,dec")
	t.Setenv("NB_INTERFACE_NAME", "test-name")
	t.Setenv("NB_ENABLE_ROSENPASS", "true")
	t.Setenv("NB_WIREGUARD_PORT", "10000")
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error while running netbird command, got %v", err)
	}
	if len(natExternalIPs) != 2 {
		t.Errorf("expected 2 external ips, got %d", len(natExternalIPs))
	}
	if natExternalIPs[0] != "abc" || natExternalIPs[1] != "dec" {
		t.Errorf("expected abc,dec, got %s,%s", natExternalIPs[0], natExternalIPs[1])
	}
	if interfaceName != "test-name" {
		t.Errorf("expected test-name, got %s", interfaceName)
	}
	if !rosenpassEnabled {
		t.Errorf("expected rosenpassEnabled to be true, got false")
	}
	if wireguardPort != 10000 {
		t.Errorf("expected wireguardPort to be 10000, got %d", wireguardPort)
	}
}

func TestSetFlagsFromEnvVarsOverridesCLI(t *testing.T) {
	var (
		parentValue string
		localValue  string
		sliceValue  []string
		boolValue   bool
	)

	// Every flag is also set on the CLI except bool-value, which is set by both WT_ and NB_.
	parent := &cobra.Command{Use: "parent"}
	parent.PersistentFlags().StringVar(&parentValue, "parent-value", "", "")

	child := &cobra.Command{
		Use: "child",
		Run: func(cmd *cobra.Command, _ []string) {
			SetFlagsFromEnvVars(cmd)
		},
	}
	child.Flags().StringVar(&localValue, "local-value", "", "")
	child.Flags().StringSliceVar(&sliceValue, "slice-value", nil, "")
	child.Flags().BoolVar(&boolValue, "bool-value", false, "")
	parent.AddCommand(child)

	t.Setenv("NB_PARENT_VALUE", "env-parent")
	t.Setenv("NB_LOCAL_VALUE", "env-local")
	t.Setenv("NB_SLICE_VALUE", "env-a,env-b")
	t.Setenv("WT_BOOL_VALUE", "false")
	t.Setenv("NB_BOOL_VALUE", "true")

	parent.SetArgs([]string{"child", "--parent-value", "cli-parent", "--local-value", "cli-local", "--slice-value", "cli-a"})
	require.NoError(t, parent.Execute())

	assert.Equal(t, "env-parent", parentValue, "env should override an inherited flag set on the CLI")
	assert.Equal(t, "env-local", localValue, "env should override a local flag set on the CLI")
	assert.Equal(t, []string{"env-a", "env-b"}, sliceValue, "env should replace a slice flag, not append to it")
	assert.True(t, boolValue, "NB_ should win over WT_")
	assert.True(t, child.Flags().Changed("bool-value"), "a flag set only from env should count as changed")
}

func TestSetFlagsFromEnvVarsIsIdempotent(t *testing.T) {
	var sliceValue []string

	cmd := &cobra.Command{Use: "cmd", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().StringSliceVar(&sliceValue, "slice-value", nil, "")
	t.Setenv("NB_SLICE_VALUE", "a,b")

	SetFlagsFromEnvVars(cmd)
	SetFlagsFromEnvVars(cmd)

	assert.Equal(t, []string{"a", "b"}, sliceValue, "binding twice should not duplicate slice values")
}
