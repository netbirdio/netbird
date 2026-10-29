package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	instanceFlag     = "instance"
	instanceRoleFlag = "instance-role"

	// envInstance selects the installation for every command except
	// "service run", whose installation comes from its registered command line
	// only: a machine-wide NB_INSTANCE must not turn the default service into a
	// copy of a named one.
	envInstance = "NB_INSTANCE"
)

var (
	instanceName    string
	instanceRoleArg string

	// instanceWarnings are logged once the daemon's log is set up.
	instanceWarnings []string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&instanceName, instanceFlag, "",
		"Named installation to act on; empty or \"default\" for the default installation. Falls back to "+envInstance+", except for 'service run'")
	serviceCmd.PersistentFlags().StringVar(&instanceRoleArg, instanceRoleFlag, "",
		"Role of a named installation, primary or secondary (default secondary). Ignored for the default installation")
}

// isEnvExempt reports whether a flag must not be set from an NB_ or WT_
// environment variable by SetFlagsFromEnvVars.
func isEnvExempt(flagName string) bool {
	return flagName == instanceFlag || flagName == instanceRoleFlag
}

// selectedInstance returns the installation name a command was given:
// --instance, else NB_INSTANCE unless the command is "service run".
func selectedInstance(cmd *cobra.Command, lookupEnv func(string) (string, bool)) string {
	if f := cmd.Flags().Lookup(instanceFlag); f != nil && f.Changed {
		return instanceName
	}
	if cmd == runCmd {
		return ""
	}
	if v, ok := lookupEnv(envInstance); ok {
		return v
	}
	return ""
}

// resolveInstance selects the installation the process acts on, makes it
// current and moves the defaults of the flags that derive from it. It runs
// before anything reads those values.
func resolveInstance(cmd *cobra.Command) error {
	inst, err := instance.For(selectedInstance(cmd, os.LookupEnv))
	if errors.Is(err, instance.ErrNamedUnsupported) {
		return err
	}
	if err != nil {
		return fmt.Errorf("invalid installation name: %w", err)
	}
	if inst.IsDefault() {
		return nil
	}

	inst = withRecordAndRole(cmd, inst)
	if err := checkServiceFlag(cmd, inst); err != nil {
		return err
	}
	if dir := inst.StateDirOverrideIgnored(); dir != "" {
		instanceWarnings = append(instanceWarnings, fmt.Sprintf(
			"%s=%s is ignored by the named installation %s, which keeps its state in %s",
			instance.EnvStateDir, dir, inst.Name(), inst.StateDir()))
	}

	def := instance.Current()
	oldConfigPath := profilemanager.DefaultConfigPath
	instance.SetCurrent(inst)
	applyInstanceDefaults(cmd, def, inst, oldConfigPath)
	return nil
}

// withRecordAndRole completes a named installation with its display label and
// role. The service learns its role from --instance-role on its command line;
// every other command reads the installation record, which the installer
// writes. A service installed by hand without a record is labelled with its
// canonical name.
func withRecordAndRole(cmd *cobra.Command, inst instance.Instance) instance.Instance {
	inst = inst.WithLabel(string(inst.Name()))

	rec, err := instance.LoadRecord(inst.Name())
	switch {
	case err == nil:
		var roleErr error
		inst, roleErr = rec.Apply(inst)
		if roleErr != nil {
			instanceWarnings = append(instanceWarnings, fmt.Sprintf("installation record: %v", roleErr))
		}
	case !errors.Is(err, instance.ErrNoRecord):
		instanceWarnings = append(instanceWarnings, fmt.Sprintf("read installation record: %v", err))
	}

	roleFlag := cmd.Flags().Lookup(instanceRoleFlag)
	if cmd == runCmd || (roleFlag != nil && roleFlag.Changed) {
		role, err := instance.ParseRole(instanceRoleArg)
		if err != nil {
			instanceWarnings = append(instanceWarnings, err.Error())
		}
		inst = inst.WithRole(role)
	}
	return inst
}

// checkServiceFlag refuses -s together with an installation whose service name
// it contradicts, rather than picking one of the two silently.
func checkServiceFlag(cmd *cobra.Command, inst instance.Instance) error {
	f := cmd.Flags().Lookup("service")
	if f == nil || !f.Changed || serviceName == inst.ServiceName() {
		return nil
	}
	return fmt.Errorf("--service %q contradicts --instance %s, whose service is %q",
		serviceName, inst.Name(), inst.ServiceName())
}

// applyInstanceDefaults moves every flag whose default derives from the
// installation to the named installation's value. A flag the user set, or one
// whose value is not the default installation's, is left alone: an explicit
// value wins.
func applyInstanceDefaults(cmd *cobra.Command, def, inst instance.Instance, oldConfigPath string) {
	unchanged := func(name string) bool {
		f := cmd.Flags().Lookup(name)
		return f == nil || !f.Changed
	}

	if unchanged("daemon-addr") && daemonAddr == def.DaemonAddr() {
		daemonAddr = inst.DaemonAddr()
	}
	if unchanged("log-file") && slices.Equal(logFiles, []string{def.LogFile()}) {
		logFiles = []string{inst.LogFile()}
	}
	defaultLogFile = inst.LogFile()
	defaultLogFileDir = inst.LogDir() + string(filepath.Separator)

	if unchanged("service") && serviceName == def.ServiceName() {
		serviceName = inst.ServiceName()
	}
	if unchanged("config") && configPath == oldConfigPath {
		configPath = profilemanager.DefaultConfigPath
	}
	if unchanged(interfaceNameFlag) && interfaceName == def.InterfaceName() {
		interfaceName = inst.InterfaceName()
	}
	if unchanged(wireguardPortFlag) && wireguardPort == def.WireGuardPort() {
		wireguardPort = inst.WireGuardPort()
	}
	if unchanged("json-socket") && jsonSocket == def.JSONSocket() {
		jsonSocket = inst.JSONSocket()
	}
	if unchanged(localMetricsAddressFlag) && localMetricsAddr == def.LocalMetricsAddr() {
		localMetricsAddr = inst.LocalMetricsAddr()
	}
}

// logInstanceWarnings logs what resolveInstance found, once the log is set up.
func logInstanceWarnings() {
	for _, w := range instanceWarnings {
		log.Warn(w)
	}
	instanceWarnings = nil
}

// checkInterfaceNameFlag enforces the rules of an explicit --interface-name in
// a named installation: the "wt" prefix that keeps the adapter out of every
// installation's ICE candidates and marks it as a NetBird adapter, and no clash
// with another adapter. The installation's own derived name is always allowed.
func checkInterfaceNameFlag(cmd *cobra.Command, exists func(string) bool) error {
	inst := instance.Current()
	f := cmd.Flags().Lookup(interfaceNameFlag)
	if inst.IsDefault() || f == nil || !f.Changed || interfaceName == inst.InterfaceName() {
		return nil
	}
	if !strings.HasPrefix(interfaceName, "wt") {
		return fmt.Errorf("interface name %q of the named installation %s must start with \"wt\"", interfaceName, inst.Name())
	}
	if exists(interfaceName) {
		return fmt.Errorf("interface %q already exists; choose a name no other adapter uses", interfaceName)
	}
	return nil
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}
