//go:build !ios && !android

package cmd

import (
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// resetInstanceState puts the package-level flag state back after a test.
func resetInstanceState(t *testing.T) {
	t.Helper()
	saved := struct {
		daemonAddr, serviceName, configPath, interfaceName, jsonSocket, localMetricsAddr string
		logFiles                                                                         []string
		wireguardPort                                                                    uint16
	}{daemonAddr, serviceName, configPath, interfaceName, jsonSocket, localMetricsAddr, logFiles, wireguardPort}
	savedDefaultLogFile, savedDefaultLogFileDir := defaultLogFile, defaultLogFileDir

	t.Cleanup(func() {
		instanceName, instanceRoleArg, instanceWarnings = "", "", nil
		for _, fs := range []*cobra.Command{rootCmd, serviceCmd} {
			for _, name := range []string{instanceFlag, instanceRoleFlag, "service"} {
				if f := fs.PersistentFlags().Lookup(name); f != nil {
					f.Changed = false
				}
			}
		}
		daemonAddr, serviceName, configPath = saved.daemonAddr, saved.serviceName, saved.configPath
		interfaceName, jsonSocket, localMetricsAddr = saved.interfaceName, saved.jsonSocket, saved.localMetricsAddr
		logFiles, wireguardPort = saved.logFiles, saved.wireguardPort
		defaultLogFile, defaultLogFileDir = savedDefaultLogFile, savedDefaultLogFileDir
		instance.SetCurrent(instance.Default())
	})
}

func namedWindowsInstance(t *testing.T, name string) instance.Instance {
	t.Helper()
	inst, err := instance.ForPlatform("windows", name)
	require.NoError(t, err)
	return inst.WithLabel(strings.ToUpper(name))
}

func env(vals map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vals[k]
		return v, ok
	}
}

// T-ID-06: the service takes its installation from --instance only; every other
// command falls back to NB_INSTANCE.
func TestSelectedInstancePrecedence(t *testing.T) {
	resetInstanceState(t)
	withEnv := env(map[string]string{envInstance: "acme"})

	require.NoError(t, runCmd.ParseFlags(nil))
	assert.Equal(t, "", selectedInstance(runCmd, withEnv), "service run ignores NB_INSTANCE")

	require.NoError(t, statusCmd.ParseFlags(nil))
	assert.Equal(t, "acme", selectedInstance(statusCmd, withEnv), "status falls back to NB_INSTANCE")
	assert.Equal(t, "", selectedInstance(statusCmd, env(nil)), "no flag and no variable: default")

	require.NoError(t, installCmd.ParseFlags(nil))
	assert.Equal(t, "acme", selectedInstance(installCmd, withEnv), "service install falls back to NB_INSTANCE")

	require.NoError(t, statusCmd.ParseFlags([]string{"--instance", "default"}))
	assert.Equal(t, "default", selectedInstance(statusCmd, withEnv), "the flag wins over NB_INSTANCE")
	inst, err := instance.For(selectedInstance(statusCmd, withEnv))
	require.NoError(t, err)
	assert.True(t, inst.IsDefault(), "--instance default selects the default installation")

	require.NoError(t, runCmd.ParseFlags([]string{"--instance", "work"}))
	assert.Equal(t, "work", selectedInstance(runCmd, withEnv), "service run takes the flag")
}

func TestInstanceFlagsAreNotSetFromEnv(t *testing.T) {
	resetInstanceState(t)
	t.Setenv("NB_INSTANCE", "acme")
	t.Setenv("WT_INSTANCE", "acme")
	t.Setenv("NB_INSTANCE_ROLE", "primary")

	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(serviceCmd)

	assert.False(t, rootCmd.PersistentFlags().Lookup(instanceFlag).Changed, "--instance must not come from the environment")
	assert.False(t, serviceCmd.PersistentFlags().Lookup(instanceRoleFlag).Changed, "--instance-role must not come from the environment")
	assert.Empty(t, instanceName, "instance name")
	assert.Empty(t, instanceRoleArg, "instance role")
}

// T-PLAT-01: a named installation fails off Windows with the specified message.
func TestNamedInstanceRejectedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named installations are supported on Windows")
	}
	resetInstanceState(t)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	rootCmd.SetArgs([]string{"--instance", "acme", "version"})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Equal(t, "named installations are supported on Windows only", err.Error(), "error message")
	assert.True(t, instance.Current().IsDefault(), "the process stays the default installation")

	rootCmd.SetArgs([]string{"--instance", "default", "version"})
	assert.NoError(t, rootCmd.Execute(), "--instance default works everywhere")
}

func TestInvalidInstanceName(t *testing.T) {
	resetInstanceState(t)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	rootCmd.SetArgs([]string{"--instance", "acme-office", "version"})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Use only letters and digits", "error message")
}

func TestApplyInstanceDefaults(t *testing.T) {
	resetInstanceState(t)
	def, err := instance.ForPlatform("windows", "")
	require.NoError(t, err)
	named := namedWindowsInstance(t, "acme")

	daemonAddr, serviceName, jsonSocket = def.DaemonAddr(), def.ServiceName(), def.JSONSocket()
	logFiles = []string{def.LogFile()}
	interfaceName, wireguardPort, localMetricsAddr = def.InterfaceName(), def.WireGuardPort(), def.LocalMetricsAddr()
	configPath = "old-default.json"

	require.NoError(t, statusCmd.ParseFlags(nil))
	applyInstanceDefaults(statusCmd, def, named, "old-default.json")

	assert.Equal(t, "npipe://netbird_acme", daemonAddr, "daemon address")
	assert.Equal(t, "Netbird_acme", serviceName, "service name")
	assert.Equal(t, []string{named.LogFile()}, logFiles, "log file")
	assert.Equal(t, "wt_acme", interfaceName, "interface name")
	assert.Equal(t, uint16(51836), wireguardPort, "WireGuard port")
	assert.Equal(t, "127.0.0.1:9207", localMetricsAddr, "metrics address")
	assert.Equal(t, "unix:///var/run/netbird_acme-http.sock", jsonSocket, "JSON socket")
}

// SBS-DEF-05, SBS-CLI-02: an explicit value overrides the derived one.
func TestApplyInstanceDefaultsKeepsExplicitValues(t *testing.T) {
	resetInstanceState(t)
	def, err := instance.ForPlatform("windows", "")
	require.NoError(t, err)
	named := namedWindowsInstance(t, "acme")

	require.NoError(t, statusCmd.ParseFlags([]string{"--daemon-addr", "npipe://netbird", "--log-file", "console"}))
	logFiles = []string{"console"}
	daemonAddr = "npipe://netbird"
	applyInstanceDefaults(statusCmd, def, named, "")

	assert.Equal(t, "npipe://netbird", daemonAddr, "explicit daemon address")
	assert.Equal(t, []string{"console"}, logFiles, "explicit log file")
	f := rootCmd.PersistentFlags().Lookup("daemon-addr")
	f.Changed = false
	rootCmd.PersistentFlags().Lookup("log-file").Changed = false
}

// T-SVC-01: the command line a named service is registered with.
func TestBuildServiceArgumentsNamed(t *testing.T) {
	resetInstanceState(t)
	named := namedWindowsInstance(t, "acme")

	logLevel, daemonAddr, configPath, managementURL = "info", named.DaemonAddr(), "", ""
	logFiles = []string{named.LogFile()}
	t.Cleanup(func() { logLevel = "info" })

	args := withInstanceArguments(named, buildServiceArguments())
	assert.Equal(t, []string{
		"service", "run", "--instance", "acme", "--instance-role", "secondary",
		"--log-level", "info", "--daemon-addr", "npipe://netbird_acme",
		"--log-file", named.LogFile(),
	}, args, "service arguments")

	assert.Equal(t, "primary", withInstanceArguments(named.WithRole(instance.RolePrimary), buildServiceArguments())[5], "role")
}

func TestBuildServiceArgumentsDefaultUnchanged(t *testing.T) {
	resetInstanceState(t)
	logLevel, daemonAddr, configPath, managementURL = "info", "npipe://netbird", "", ""
	logFiles = []string{`C:\ProgramData\Netbird\client.log`}
	t.Cleanup(func() { logLevel = "info" })

	assert.Equal(t, []string{
		"service", "run", "--log-level", "info", "--daemon-addr", "npipe://netbird",
		"--log-file", `C:\ProgramData\Netbird\client.log`,
	}, withInstanceArguments(instance.Default(), buildServiceArguments()), "service arguments of the default installation")
}

// SBS-SVC-02: -s that contradicts --instance is an error.
func TestCheckServiceFlag(t *testing.T) {
	resetInstanceState(t)
	named := namedWindowsInstance(t, "acme")

	require.NoError(t, statusCmd.ParseFlags(nil))
	assert.NoError(t, checkServiceFlag(statusCmd, named), "no -s")

	require.NoError(t, statusCmd.ParseFlags([]string{"-s", "Netbird_acme"}))
	assert.NoError(t, checkServiceFlag(statusCmd, named), "-s that matches")

	require.NoError(t, statusCmd.ParseFlags([]string{"-s", "Netbird"}))
	assert.Error(t, checkServiceFlag(statusCmd, named), "-s that contradicts")
}

// SBS-SVC-07: a named daemon never serves the legacy loopback address.
func TestRefuseLegacyAddrForNamed(t *testing.T) {
	named := namedWindowsInstance(t, "acme")
	legacy := instance.Default().LegacyTCPDaemonAddr()
	if legacy == "" {
		t.Skip("the legacy address exists only on Windows")
	}
	assert.Error(t, refuseLegacyAddrForNamed(named, legacy), "named on the legacy address")
	assert.NoError(t, refuseLegacyAddrForNamed(named, named.DaemonAddr()), "named on its pipe")
	assert.NoError(t, refuseLegacyAddrForNamed(instance.Default(), legacy), "default on the legacy address")
}

// SBS-NET-02: an explicit interface name of a named installation.
func TestCheckInterfaceNameFlag(t *testing.T) {
	resetInstanceState(t)
	instance.SetCurrent(namedWindowsInstance(t, "acme"))
	existing := func(name string) bool { return name == "wt0" }

	check := func(args ...string) error {
		require.NoError(t, upCmd.ParseFlags(args))
		t.Cleanup(func() { upCmd.PersistentFlags().Lookup(interfaceNameFlag).Changed = false })
		return checkInterfaceNameFlag(upCmd, existing)
	}

	assert.NoError(t, check(), "no flag")
	assert.Error(t, check("--interface-name", "nb1"), "missing wt prefix")
	assert.Error(t, check("--interface-name", "wt0"), "name of another adapter")
	assert.NoError(t, check("--interface-name", "wt_x"), "free name")
	assert.NoError(t, check("--interface-name", "wt_acme"), "own derived name")
}

func TestCheckInterfaceNameFlagDefaultUnchanged(t *testing.T) {
	resetInstanceState(t)
	require.NoError(t, upCmd.ParseFlags([]string{"--interface-name", "nb1"}))
	t.Cleanup(func() { upCmd.PersistentFlags().Lookup(interfaceNameFlag).Changed = false })
	assert.NoError(t, checkInterfaceNameFlag(upCmd, func(string) bool { return true }), "default installation")
}
