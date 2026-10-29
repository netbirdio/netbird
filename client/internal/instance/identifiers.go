package instance

import (
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	goosWindows = "windows"
	goosDarwin  = "darwin"
	goosFreeBSD = "freebsd"

	envProgramData = "PROGRAMDATA"
	// EnvStateDir overrides the state directory of the default installation.
	EnvStateDir = "NB_STATE_DIR"

	// defaultAdapterGUID is also the UUIDv5 namespace of every derived GUID.
	defaultAdapterGUID = "f2f29e61-d91f-4d76-8151-119b20c4bdeb"

	uuidAdapter        = "adapter"
	uuidToastActivator = "toast-activator"

	portSlots = 100

	baseWireGuardPort uint16 = 51820
	baseMetricsPort   uint16 = 9191
	basePprofPort     uint16 = 6969
	baseSocks5Port    uint16 = 1080
)

// Marker returns the qualifier "_<name>" every named identifier carries after
// its product token, and the empty string for the default installation.
func (i Instance) Marker() string {
	if i.IsDefault() {
		return ""
	}
	return "_" + string(i.name)
}

// ServiceName returns the system service name.
func (i Instance) ServiceName() string {
	if i.goos == goosWindows {
		return "Netbird" + i.Marker()
	}
	return "netbird"
}

// ServiceDisplayName returns the service display name. The Service Control
// Manager requires it to be unique, so it carries the label.
func (i Instance) ServiceDisplayName() string {
	if i.IsDefault() {
		return "Netbird"
	}
	return i.DisplayName()
}

// ServiceDescription returns the service description.
func (i Instance) ServiceDescription() string {
	return "NetBird mesh network client" + i.labelSuffix()
}

// DisplayName returns the product name as shown to people: "NetBird", or
// "NetBird (ACME)" for a named installation.
func (i Instance) DisplayName() string {
	return "NetBird" + i.labelSuffix()
}

func (i Instance) labelSuffix() string {
	if i.IsDefault() {
		return ""
	}
	return " (" + i.label + ")"
}

// DaemonAddr returns the address the daemon serves its gRPC API on. On Windows it
// is a named pipe: a pipe carries the connecting process's token, which loopback
// TCP does not, so it is the only transport on which the daemon can tell who is
// calling it.
func (i Instance) DaemonAddr() string {
	if i.goos == goosWindows {
		return "npipe://netbird" + i.Marker()
	}
	return "unix:///var/run/netbird.sock"
}

// LegacyTCPDaemonAddr returns the loopback address the Windows daemon used before
// named pipes, or the empty string when there is none to probe or migrate. Only
// the default installation ever had one.
func (i Instance) LegacyTCPDaemonAddr() string {
	if i.goos != goosWindows || !i.IsDefault() {
		return ""
	}
	return "tcp://127.0.0.1:41731"
}

// JSONSocket returns the default address of the opt-in HTTP/JSON gateway.
func (i Instance) JSONSocket() string {
	return "unix:///var/run/netbird" + i.Marker() + "-http.sock"
}

// StateDir returns the daemon's state directory. NB_STATE_DIR overrides it for
// the default installation only; see StateDirOverrideIgnored.
func (i Instance) StateDir() string {
	if i.IsDefault() {
		if dir := i.getenv(EnvStateDir); dir != "" {
			return dir
		}
	}
	switch i.goos {
	case goosWindows:
		return i.machineDir()
	case goosDarwin, "linux":
		return "/var/lib/netbird"
	case goosFreeBSD, "openbsd", "netbsd", "dragonfly":
		return "/var/db/netbird"
	default:
		return ""
	}
}

// StateDirOverrideIgnored returns the NB_STATE_DIR value a named installation
// ignores, so the caller can warn about it, or the empty string.
func (i Instance) StateDirOverrideIgnored() string {
	if i.IsDefault() {
		return ""
	}
	return i.getenv(EnvStateDir)
}

// ProfileDir returns the directory of the daemon's profile files, formatted as
// the profile manager always has. It equals StateDir on Windows.
func (i Instance) ProfileDir() string {
	if !i.IsDefault() {
		return i.StateDir()
	}
	if dir := i.getenv(EnvStateDir); dir != "" {
		return dir
	}
	switch i.goos {
	case goosWindows:
		return i.machineDir()
	case goosFreeBSD:
		return "/var/db/netbird/"
	default:
		return "/var/lib/netbird/"
	}
}

// LegacyProfileDir returns where the profile manager looks for a config.json
// written by releases before profiles.
func (i Instance) LegacyProfileDir() string {
	if !i.IsDefault() {
		return i.StateDir()
	}
	if i.getenv(EnvStateDir) != "" {
		return "/etc/netbird/"
	}
	switch i.goos {
	case goosWindows:
		return i.machineDir()
	case goosFreeBSD:
		return "/var/db/netbird/"
	default:
		return "/etc/netbird/"
	}
}

// LegacyConfigDir returns the directory of the CLI's pre-profile config.json, the
// target of the Wiretrustee rebrand migration.
func (i Instance) LegacyConfigDir() string {
	switch i.goos {
	case goosWindows:
		return i.machineDir()
	case goosFreeBSD:
		return "/var/db/netbird"
	default:
		return "/etc/netbird"
	}
}

// LogDir returns the daemon's log directory. It ignores NB_STATE_DIR.
func (i Instance) LogDir() string {
	if i.goos == goosWindows {
		return i.machineDir()
	}
	return "/var/log/netbird"
}

// LogFile returns the daemon's default log file.
func (i Instance) LogFile() string {
	return i.join(i.LogDir(), "client.log")
}

// PanicLogFile returns the file the Windows daemon redirects stderr to, or the
// empty string on other platforms.
func (i Instance) PanicLogFile() string {
	if i.goos != goosWindows {
		return ""
	}
	return i.join(i.machineDir(), "netbird.err")
}

// UpdaterTempDir returns the folder the updater downloads installers to, or the
// empty string where there is no updater.
func (i Instance) UpdaterTempDir() string {
	switch i.goos {
	case goosWindows:
		return i.join(i.machineDir(), "tmp-install")
	case goosDarwin:
		return "/var/lib/netbird/tmp-install"
	default:
		return ""
	}
}

// UserDirName returns the name of the per-user directory under the OS user
// config directory, which holds the CLI's and the UI's own files.
func (i Instance) UserDirName() string {
	return "netbird" + i.Marker()
}

// DebugBundlePattern returns the os.CreateTemp pattern of debug bundle zips.
func (i Instance) DebugBundlePattern() string {
	return "netbird" + i.Marker() + ".debug.*.zip"
}

// ExportedDebugBundlePrefix returns the name prefix of exported debug bundles.
func (i Instance) ExportedDebugBundlePrefix() string {
	return "netbird" + i.Marker() + ".debug-file."
}

// KubeUser returns the user entry name NetBird writes into a kubeconfig.
func (i Instance) KubeUser() string {
	return "netbird" + i.Marker()
}

// AdapterGUID returns the Windows adapter GUID in registry form.
func (i Instance) AdapterGUID() string {
	if i.IsDefault() {
		return "{" + defaultAdapterGUID + "}"
	}
	return i.derivedUUID(uuidAdapter)
}

// ToastActivatorCLSID returns the COM class the UI registers as its toast
// activator, or the empty string for the default installation, whose CLSID the
// MSI pre-seeds or the UI library generates.
func (i Instance) ToastActivatorCLSID() string {
	if i.IsDefault() {
		return ""
	}
	return i.derivedUUID(uuidToastActivator)
}

// InterfaceName returns the default overlay interface name.
func (i Instance) InterfaceName() string {
	if !i.IsDefault() {
		return "wt" + i.Marker()
	}
	if i.goos == goosDarwin {
		return "utun100"
	}
	return "wt0"
}

// WireGuardPort returns the default WireGuard listen port.
func (i Instance) WireGuardPort() uint16 {
	return baseWireGuardPort + i.portOffset()
}

// LocalMetricsAddr returns the default address of the opt-in metrics endpoint.
func (i Instance) LocalMetricsAddr() string {
	return "127.0.0.1:" + strconv.Itoa(int(baseMetricsPort+i.portOffset()))
}

// PprofAddr returns the default pprof listen address of pprof-tagged builds.
func (i Instance) PprofAddr() string {
	return "localhost:" + strconv.Itoa(int(basePprofPort+i.portOffset()))
}

// Socks5Port returns the default port of the netstack-mode SOCKS5 proxy.
func (i Instance) Socks5Port() uint16 {
	return baseSocks5Port + i.portOffset()
}

// NRPTKeyPrefix starts the name of every NRPT rule key the installation owns.
// Cleanup matches it case-insensitively.
func (i Instance) NRPTKeyPrefix() string {
	return "NetBird" + i.Marker() + "-"
}

// FirewallRuleName returns the name of the Windows Firewall inbound rule.
func (i Instance) FirewallRuleName() string {
	return "Netbird" + i.Marker()
}

// FirewallRuleNameV6 returns the name of the IPv6 Windows Firewall inbound rule.
func (i Instance) FirewallRuleNameV6() string {
	return i.FirewallRuleName() + "-v6"
}

// SSHConfigFile returns the file name of the OpenSSH client config include.
func (i Instance) SSHConfigFile() string {
	return "99-netbird" + i.Marker() + ".conf"
}

// UIUniqueID returns the single-instance identifier of the tray UI.
func (i Instance) UIUniqueID() string {
	if i.IsDefault() {
		return "io.netbird.ui"
	}
	return "io.netbird.ui." + string(i.name)
}

// UIAppName returns the UI application name, which on Windows is also its
// AppUserModelID.
func (i Instance) UIAppName() string {
	return "NetBird" + i.Marker()
}

// AutostartName returns the HKCU Run value name of the UI's autostart entry.
func (i Instance) AutostartName() string {
	return "netbird" + i.Marker()
}

// AutostartArguments returns the arguments the UI's autostart entry passes.
func (i Instance) AutostartArguments() []string {
	if i.IsDefault() {
		return nil
	}
	return []string{"--instance", string(i.name)}
}

// WebviewDataDirName returns the folder, relative to the per-user directory,
// that holds a named UI's WebView2 data, or the empty string for the default
// UI, which keeps the library's default folder.
func (i Instance) WebviewDataDirName() string {
	if i.IsDefault() {
		return ""
	}
	return "webview2"
}

// QuickActionsEvent returns the named event that brings the UI window up.
func (i Instance) QuickActionsEvent() string {
	return `Global\NetBird` + i.Marker() + `QuickActionsTriggerEvent`
}

// DebugTriggerEvent returns the named event that makes the daemon write a debug
// bundle.
func (i Instance) DebugTriggerEvent() string {
	return `Global\Netbird` + i.Marker() + `DebugTriggerEvent`
}

// CLIFlag returns the global flag that addresses this installation from the
// CLI, or the empty string for the default installation.
func (i Instance) CLIFlag() string {
	if i.IsDefault() {
		return ""
	}
	return "--instance " + string(i.name)
}

// CLICommand renders a netbird command line that acts on this installation,
// for hints that users copy and paste.
func (i Instance) CLICommand(args string) string {
	if flag := i.CLIFlag(); flag != "" {
		return "netbird " + flag + " " + args
	}
	return "netbird " + args
}

// RecordKey returns the HKLM path of the installation record, or the empty
// string for the default installation, which has none.
func (i Instance) RecordKey() string {
	if i.IsDefault() {
		return ""
	}
	return recordsKey + `\` + string(i.name)
}

// machineDir is the per-installation folder under ProgramData, which the log,
// the panic log and the updater use even when NB_STATE_DIR moves the state.
func (i Instance) machineDir() string {
	return i.join(i.getenv(envProgramData), "Netbird"+i.Marker())
}

// portOffset is k = 1 + FNV-1a-32(name) mod 100, so a named installation never
// takes a default port.
func (i Instance) portOffset() uint16 {
	if i.IsDefault() {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(i.name))
	return uint16(1 + h.Sum32()%portSlots)
}

func (i Instance) derivedUUID(purpose string) string {
	ns := uuid.MustParse(defaultAdapterGUID)
	return "{" + uuid.NewSHA1(ns, []byte(purpose+"/"+string(i.name))).String() + "}"
}

// join joins path elements with the separator of the installation's platform,
// so every platform's identifiers can be derived and tested on any host.
func (i Instance) join(elem ...string) string {
	sep := "/"
	if i.goos == goosWindows {
		sep = `\`
	}
	var parts []string
	for n, e := range elem {
		if n > 0 {
			e = strings.TrimLeft(e, `\/`)
		}
		if n < len(elem)-1 {
			e = strings.TrimRight(e, `\/`)
		}
		if e != "" {
			parts = append(parts, e)
		}
	}
	return strings.Join(parts, sep)
}
