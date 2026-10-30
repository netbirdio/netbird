package instance_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/configs"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/internal/localmetrics"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// T-DEF-01. The values below are copied from NetBird v0.81.5 (396976b8b) and are
// the contract of the default installation (SBS-DEF-01). Never change them: a
// difference means the default installation changed, not that the test is stale.

const goldenProgramData = `C:\ProgramData`

// v0815Default returns the v0.81.5 identifiers of the default installation for
// goos, with PROGRAMDATA set to goldenProgramData and NB_STATE_DIR set to
// stateDirEnv (empty means unset).
func v0815Default(goos, stateDirEnv string) map[string]string {
	g := map[string]string{
		"daemonAddr":       "unix:///var/run/netbird.sock",
		"serviceName":      "netbird",
		"serviceDisplay":   "Netbird",
		"serviceDesc":      "NetBird mesh network client",
		"jsonSocket":       "unix:///var/run/netbird-http.sock",
		"logFile":          "/var/log/netbird/client.log",
		"legacyConfigDir":  "/etc/netbird",
		"stateDir":         "",
		"profileDir":       "/var/lib/netbird/",
		"legacyProfileDir": "/etc/netbird/",
		"interfaceName":    "wt0",
		"wireguardPort":    "51820",
		"localMetrics":     "127.0.0.1:9191",
		"pprof":            "localhost:6969",
		"socks5Port":       "1080",
		"sshConfigFile":    "99-netbird.conf",
		"userDirName":      "netbird",
		"kubeUser":         "netbird",
		"bundlePattern":    "netbird.debug.*.zip",
		"bundleExported":   "netbird.debug-file.",
		"uiUniqueID":       "io.netbird.ui",
		"uiAppName":        "NetBird",
		"displayName":      "NetBird",
	}

	switch goos {
	case "windows":
		g["daemonAddr"] = "npipe://netbird"
		g["legacyTCPAddr"] = "tcp://127.0.0.1:41731"
		g["serviceName"] = "Netbird"
		g["logFile"] = goldenProgramData + `\Netbird\client.log`
		g["legacyConfigDir"] = goldenProgramData + `\Netbird`
		g["stateDir"] = goldenProgramData + `\Netbird`
		g["profileDir"] = goldenProgramData + `\Netbird`
		g["legacyProfileDir"] = goldenProgramData + `\Netbird`
		g["panicLog"] = goldenProgramData + `\Netbird\netbird.err`
		g["updaterTempDir"] = goldenProgramData + `\Netbird\tmp-install`
		g["adapterGUID"] = "{f2f29e61-d91f-4d76-8151-119b20c4bdeb}"
		g["nrptPrefix"] = "NetBird-"
		g["firewallRule"] = "Netbird"
		g["firewallRuleV6"] = "Netbird-v6"
		g["quickActionsEvent"] = `Global\NetBirdQuickActionsTriggerEvent`
		g["debugEvent"] = `Global\NetbirdDebugTriggerEvent`
	case "darwin":
		g["stateDir"] = "/var/lib/netbird"
		g["interfaceName"] = "utun100"
		g["updaterTempDir"] = "/var/lib/netbird/tmp-install"
	case "linux":
		g["stateDir"] = "/var/lib/netbird"
	case "freebsd":
		g["stateDir"] = "/var/db/netbird"
		g["profileDir"] = "/var/db/netbird/"
		g["legacyProfileDir"] = "/var/db/netbird/"
		g["legacyConfigDir"] = "/var/db/netbird"
	case "openbsd", "netbsd", "dragonfly":
		g["stateDir"] = "/var/db/netbird"
	}

	if stateDirEnv != "" {
		g["stateDir"] = stateDirEnv
		g["profileDir"] = stateDirEnv
		g["legacyProfileDir"] = "/etc/netbird/"
	}
	return g
}

var goldenOSes = []string{"windows", "linux", "darwin", "freebsd", "openbsd", "android", "ios", "js"}

// TestDefaultGoldenV0815 compares the identity package with the v0.81.5 table on
// every platform, with and without NB_STATE_DIR.
func TestDefaultGoldenV0815(t *testing.T) {
	for _, goos := range goldenOSes {
		for _, stateDirEnv := range []string{"", "/srv/nbstate"} {
			t.Run(goos+"/NB_STATE_DIR="+stateDirEnv, func(t *testing.T) {
				env := map[string]string{"PROGRAMDATA": goldenProgramData, "NB_STATE_DIR": stateDirEnv}
				inst := instance.NewForOS(goos, env, instance.DefaultName, "")
				want := v0815Default(goos, stateDirEnv)
				got := defaultIdentifiers(inst)
				for key, w := range want {
					assert.Equal(t, w, got[key], "identifier %s", key)
				}
				for key, g := range got {
					if _, ok := want[key]; !ok {
						assert.Empty(t, g, "identifier %s has no v0.81.5 value on %s", key, goos)
					}
				}
			})
		}
	}
}

// TestDefaultIsCurrent checks that a process that was given no installation runs
// as the default one.
func TestDefaultIsCurrent(t *testing.T) {
	assert.True(t, instance.Current().IsDefault(), "current installation")
	assert.Equal(t, defaultIdentifiers(instance.Default()), defaultIdentifiers(instance.Current()), "current installation")
	inst, err := instance.For("")
	assert.NoError(t, err)
	assert.Equal(t, defaultIdentifiers(instance.Default()), defaultIdentifiers(inst), "For(\"\")")
}

func defaultIdentifiers(i instance.Instance) map[string]string {
	return map[string]string{
		"daemonAddr":        i.DaemonAddr(),
		"legacyTCPAddr":     i.LegacyTCPDaemonAddr(),
		"serviceName":       i.ServiceName(),
		"serviceDisplay":    i.ServiceDisplayName(),
		"serviceDesc":       i.ServiceDescription(),
		"jsonSocket":        i.JSONSocket(),
		"logFile":           i.LogFile(),
		"legacyConfigDir":   i.LegacyConfigDir(),
		"stateDir":          i.StateDir(),
		"profileDir":        i.ProfileDir(),
		"legacyProfileDir":  i.LegacyProfileDir(),
		"panicLog":          i.PanicLogFile(),
		"updaterTempDir":    i.UpdaterTempDir(),
		"interfaceName":     i.InterfaceName(),
		"wireguardPort":     strconv.Itoa(int(i.WireGuardPort())),
		"localMetrics":      i.LocalMetricsAddr(),
		"pprof":             i.PprofAddr(),
		"socks5Port":        strconv.Itoa(int(i.Socks5Port())),
		"sshConfigFile":     i.SSHConfigFile(),
		"userDirName":       i.UserDirName(),
		"kubeUser":          i.KubeUser(),
		"bundlePattern":     i.DebugBundlePattern(),
		"bundleExported":    i.ExportedDebugBundlePrefix(),
		"uiUniqueID":        i.UIUniqueID(),
		"uiAppName":         i.UIAppName(),
		"displayName":       i.DisplayName(),
		"adapterGUID":       windowsOnly(i, i.AdapterGUID()),
		"nrptPrefix":        windowsOnly(i, i.NRPTKeyPrefix()),
		"firewallRule":      windowsOnly(i, i.FirewallRuleName()),
		"firewallRuleV6":    windowsOnly(i, i.FirewallRuleNameV6()),
		"quickActionsEvent": windowsOnly(i, i.QuickActionsEvent()),
		"debugEvent":        windowsOnly(i, i.DebugTriggerEvent()),
		"toastActivator":    i.ToastActivatorCLSID(),
		"marker":            i.Marker(),
		"label":             i.Label(),
		"role":              roleIfNotPrimary(i),
	}
}

// windowsOnly blanks identifiers that exist only on Windows, so the table lists
// each one where v0.81.5 has it.
func windowsOnly(i instance.Instance, v string) string {
	if instance.ExportGOOS(i) != "windows" {
		return ""
	}
	return v
}

func roleIfNotPrimary(i instance.Instance) string {
	if i.Role() == instance.RolePrimary {
		return ""
	}
	return string(i.Role())
}

// TestDefaultConsumersV0815 checks the values today's consumers expose on the
// host, so the table above is anchored to the code and not only to itself.
func TestDefaultConsumersV0815(t *testing.T) {
	stateDirEnv := os.Getenv("NB_STATE_DIR")
	want := v0815Default(runtime.GOOS, stateDirEnv)
	if runtime.GOOS == "windows" {
		want = v0815DefaultHost(stateDirEnv)
	}

	assert.Equal(t, want["stateDir"], configs.StateDir, "configs.StateDir")
	assert.Equal(t, want["profileDir"], profilemanager.DefaultConfigPathDir, "profilemanager.DefaultConfigPathDir")
	assert.Equal(t, filepath.Join(want["profileDir"], "default.json"), profilemanager.DefaultConfigPath, "profilemanager.DefaultConfigPath")
	assert.Equal(t, filepath.Join(want["profileDir"], "active_profile.json"), profilemanager.ActiveProfileStatePath, "profilemanager.ActiveProfileStatePath")
	assert.Equal(t, want["wireguardPort"], strconv.Itoa(iface.DefaultWgPort), "WireGuard port")
	assert.Equal(t, want["localMetrics"], localmetrics.DefaultListenAddress(), "local metrics address")
	assert.Equal(t, want["socks5Port"], strconv.Itoa(netstack.DefaultSocks5Port()), "SOCKS5 port")
}

// v0815DefaultHost is v0815Default with the host's real PROGRAMDATA, for the
// consumer check on Windows.
func v0815DefaultHost(stateDirEnv string) map[string]string {
	g := v0815Default("windows", stateDirEnv)
	pd := os.Getenv("PROGRAMDATA")
	for k, v := range g {
		if rest, ok := strings.CutPrefix(v, goldenProgramData); ok {
			g[k] = filepath.Join(pd, rest)
		}
	}
	return g
}
