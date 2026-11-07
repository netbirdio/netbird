package instance

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testEnv = map[string]string{"PROGRAMDATA": `C:\ProgramData`}

func windowsInstance(t testing.TB, input string, env map[string]string) Instance {
	t.Helper()
	name, label, err := ParseName(input)
	require.NoError(t, err)
	return newInstance(goosWindows, func(k string) string { return env[k] }, name, label)
}

// T-ID-01: the identifiers of the named installation acme, as in the identifier
// matrix.
func TestNamedIdentifiers(t *testing.T) {
	env := map[string]string{"PROGRAMDATA": `C:\ProgramData`, EnvStateDir: `C:\x`}
	i := windowsInstance(t, "ACME", env)

	want := map[string]string{
		"name":              "acme",
		"label":             "ACME",
		"marker":            "_acme",
		"role":              "secondary",
		"serviceName":       "Netbird_acme",
		"serviceDisplay":    "NetBird (ACME)",
		"serviceDesc":       "NetBird mesh network client (ACME)",
		"displayName":       "NetBird (ACME)",
		"daemonAddr":        "npipe://netbird_acme",
		"legacyTCPAddr":     "",
		"jsonSocket":        "unix:///var/run/netbird_acme-http.sock",
		"stateDir":          `C:\ProgramData\Netbird_acme`,
		"ignoredStateDir":   `C:\x`,
		"profileDir":        `C:\ProgramData\Netbird_acme`,
		"logFile":           `C:\ProgramData\Netbird_acme\client.log`,
		"panicLog":          `C:\ProgramData\Netbird_acme\netbird.err`,
		"updaterTempDir":    `C:\ProgramData\Netbird_acme\tmp-install`,
		"userDirName":       "netbird_acme",
		"bundlePattern":     "netbird_acme.debug.*.zip",
		"kubeUser":          "netbird_acme",
		"adapterGUID":       "{930adb3f-6a74-541d-b49f-0166bb47c7a5}",
		"toastActivator":    "{5a3724b5-05f1-5ac3-9c29-1d659e422484}",
		"interfaceName":     "wt_acme",
		"wireguardPort":     "51836",
		"localMetrics":      "127.0.0.1:9207",
		"pprof":             "localhost:6985",
		"socks5Port":        "1096",
		"nrptPrefix":        "NetBird_acme-",
		"firewallRule":      "Netbird_acme",
		"firewallRuleV6":    "Netbird_acme-v6",
		"sshConfigFile":     "99-netbird_acme.conf",
		"uiUniqueID":        "io.netbird.ui.acme",
		"uiAppName":         "NetBird_acme",
		"quickActionsEvent": `Global\NetBird_acmeQuickActionsTriggerEvent`,
		"debugEvent":        `Global\Netbird_acmeDebugTriggerEvent`,
	}
	got := map[string]string{
		"name":              string(i.Name()),
		"label":             i.Label(),
		"marker":            i.Marker(),
		"role":              string(i.Role()),
		"serviceName":       i.ServiceName(),
		"serviceDisplay":    i.ServiceDisplayName(),
		"serviceDesc":       i.ServiceDescription(),
		"displayName":       i.DisplayName(),
		"daemonAddr":        i.DaemonAddr(),
		"legacyTCPAddr":     i.LegacyTCPDaemonAddr(),
		"jsonSocket":        i.JSONSocket(),
		"stateDir":          i.StateDir(),
		"ignoredStateDir":   i.StateDirOverrideIgnored(),
		"profileDir":        i.ProfileDir(),
		"logFile":           i.LogFile(),
		"panicLog":          i.PanicLogFile(),
		"updaterTempDir":    i.UpdaterTempDir(),
		"userDirName":       i.UserDirName(),
		"bundlePattern":     i.DebugBundlePattern(),
		"kubeUser":          i.KubeUser(),
		"adapterGUID":       i.AdapterGUID(),
		"toastActivator":    i.ToastActivatorCLSID(),
		"interfaceName":     i.InterfaceName(),
		"wireguardPort":     fmt.Sprint(i.WireGuardPort()),
		"localMetrics":      i.LocalMetricsAddr(),
		"pprof":             i.PprofAddr(),
		"socks5Port":        fmt.Sprint(i.Socks5Port()),
		"nrptPrefix":        i.NRPTKeyPrefix(),
		"firewallRule":      i.FirewallRuleName(),
		"firewallRuleV6":    i.FirewallRuleNameV6(),
		"sshConfigFile":     i.SSHConfigFile(),
		"uiUniqueID":        i.UIUniqueID(),
		"uiAppName":         i.UIAppName(),
		"quickActionsEvent": i.QuickActionsEvent(),
		"debugEvent":        i.DebugTriggerEvent(),
	}
	assert.Equal(t, want, got, "identifiers of acme")
	assert.False(t, i.IsDefault(), "acme is not the default installation")
}

// T-ID-02: name validation with the messages of the installer specification.
func TestParseName(t *testing.T) {
	tests := []struct {
		input     string
		wantName  Name
		wantLabel string
		wantErr   string
	}{
		{input: "", wantName: DefaultName},
		{input: "default", wantName: DefaultName},
		{input: "DEFAULT", wantName: DefaultName},
		{input: "acme", wantName: "acme", wantLabel: "acme"},
		{input: "ACME", wantName: "acme", wantLabel: "ACME"},
		{input: "AcMe2", wantName: "acme2", wantLabel: "AcMe2"},
		{input: "a", wantName: "a", wantLabel: "a"},
		{input: "abcdefghijkl", wantName: "abcdefghijkl", wantLabel: "abcdefghijkl"},
		{input: "2nd", wantErr: "The name must start with a letter."},
		{input: "acme-office", wantErr: "Use only letters and digits (no spaces, hyphens or underscores)."},
		{input: "acme_office", wantErr: "Use only letters and digits (no spaces, hyphens or underscores)."},
		{input: "acme office", wantErr: "Use only letters and digits (no spaces, hyphens or underscores)."},
		{input: "acmé", wantErr: "Use only letters and digits (no spaces, hyphens or underscores)."},
		{input: "İx", wantErr: "Use only letters and digits (no spaces, hyphens or underscores)."},
		{input: `..\x`, wantErr: "Use only letters and digits (no spaces, hyphens or underscores)."},
		{input: "acmeofficenetwork", wantErr: "The name can be at most 12 characters long."},
		{input: "abcdefghijklm", wantErr: "The name can be at most 12 characters long."},
		{input: "netbird", wantErr: `"netbird" is reserved. Choose another name.`},
		{input: "NetBird", wantErr: `"netbird" is reserved. Choose another name.`},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			name, label, err := ParseName(tc.input)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error(), "message for %q", tc.input)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, name, "name of %q", tc.input)
			assert.Equal(t, tc.wantLabel, label, "label of %q", tc.input)
		})
	}

	assert.EqualError(t, ValidateName(""), "Enter a name for this installation.")
	assert.EqualError(t, ValidateName("default"), `"default" is reserved. Choose another name.`)
}

func TestForRejectsNamedOffWindows(t *testing.T) {
	inst, err := For("acme")
	if goosOfHost() == goosWindows {
		require.NoError(t, err)
		assert.Equal(t, Name("acme"), inst.Name(), "name")
		return
	}
	assert.ErrorIs(t, err, ErrNamedUnsupported)
	assert.EqualError(t, err, "named installations are supported on Windows only")

	_, err = For("acme-office")
	assert.Error(t, err, "an invalid name is rejected before the platform check")
}

// FuzzParseName checks that every accepted name yields identifiers that are
// valid for their kind.
func FuzzParseName(f *testing.F) {
	for _, s := range []string{"acme", "ACME", "a", "abcdefghijkl", "a-b", "", "default", "x\x00", "ÄB", "a.b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		name, _, err := ParseName(input)
		if err != nil || name == DefaultName {
			return
		}
		i := windowsInstance(t, input, testEnv)
		assertValidIdentifiers(t, i)
	})
}

func assertValidIdentifiers(t *testing.T, i Instance) {
	t.Helper()
	const fileForbidden = `\/:*?"<>|`
	for _, v := range []string{i.ServiceName(), i.FirewallRuleName(), i.FirewallRuleNameV6(),
		i.SSHConfigFile(), i.UserDirName(), i.UIAppName(), i.NRPTKeyPrefix() + "Match-0", i.KubeUser()} {
		assert.False(t, strings.ContainsAny(v, fileForbidden+" \x00"), "%q has a forbidden character", v)
	}
	assert.LessOrEqual(t, len(i.ServiceName()), 256, "service name length")
	assert.LessOrEqual(t, len(i.InterfaceName()), 15, "interface name length")
	assert.True(t, strings.HasPrefix(i.InterfaceName(), "wt"), "interface name prefix")

	pipe, ok := strings.CutPrefix(i.DaemonAddr(), "npipe://")
	assert.True(t, ok, "daemon address scheme")
	assert.False(t, strings.ContainsAny(pipe, `\/`), "pipe name %q", pipe)

	for _, dir := range []string{i.StateDir(), i.LogDir()} {
		rest, ok := strings.CutPrefix(dir, `C:\ProgramData\`)
		assert.True(t, ok, "%q is under ProgramData", dir)
		assert.False(t, strings.ContainsAny(rest, fileForbidden+" ."), "%q stays one folder", rest)
	}
	for _, ev := range []string{i.QuickActionsEvent(), i.DebugTriggerEvent()} {
		rest, ok := strings.CutPrefix(ev, `Global\`)
		assert.True(t, ok, "event %q is global", ev)
		assert.NotContains(t, rest, `\`, "event %q", ev)
	}
	port := i.WireGuardPort()
	assert.True(t, port > 51820 && port <= 51920, "port %d", port)
}

// T-ID-03: named identifiers never equal or match another installation's.
func TestDisjointIdentifiers(t *testing.T) {
	names := []string{"a", "ab", "a1", "v6", "abcdefghijkl", "abcdefghijk", "acme", "acme2", "work", "globex"}
	def := newInstance(goosWindows, func(k string) string { return testEnv[k] }, DefaultName, "")

	owner := map[string]string{}
	add := func(who string, i Instance) {
		for _, v := range identifierSet(i) {
			key := strings.ToLower(v)
			prev, seen := owner[key]
			assert.False(t, seen && prev != who, "%q is used by %s and %s", v, prev, who)
			owner[key] = who
		}
	}
	add("default", def)
	for _, n := range names {
		i := windowsInstance(t, n, testEnv)
		add(n, i)
		// Ports have 100 slots, so two names can share one and the existing
		// fallback to a free port applies; they never take the default's.
		assert.NotEqual(t, def.WireGuardPort(), i.WireGuardPort(), "WireGuard port of %s", n)
		assert.NotEqual(t, def.LocalMetricsAddr(), i.LocalMetricsAddr(), "metrics address of %s", n)
		assert.NotEqual(t, def.PprofAddr(), i.PprofAddr(), "pprof address of %s", n)
		assert.NotEqual(t, def.Socks5Port(), i.Socks5Port(), "SOCKS5 port of %s", n)
	}

	for _, a := range names {
		ia := windowsInstance(t, a, testEnv)
		for _, key := range nrptKeys(ia) {
			// The v0.81.5 NRPT cleanup: case-insensitive prefix "netbird-".
			assert.False(t, strings.HasPrefix(strings.ToLower(key), "netbird-"), "default cleanup matches %q", key)
		}
		// The v0.81.5 firewall: exact names.
		assert.NotEqual(t, "Netbird", ia.FirewallRuleName(), "firewall rule")
		assert.NotEqual(t, "Netbird-v6", ia.FirewallRuleNameV6(), "firewall v6 rule")
		// The ICE blacklist: prefix "wt", on purpose.
		assert.True(t, strings.HasPrefix(ia.InterfaceName(), "wt"), "ICE blacklist excludes %s", ia.InterfaceName())

		for _, b := range names {
			if a == b {
				continue
			}
			ib := windowsInstance(t, b, testEnv)
			for _, key := range nrptKeys(ib) {
				assert.False(t, strings.HasPrefix(strings.ToLower(key), strings.ToLower(ia.NRPTKeyPrefix())),
					"cleanup of %s matches %s's key %q", a, b, key)
			}
		}
	}
	for _, key := range nrptKeys(def) {
		for _, n := range names {
			i := windowsInstance(t, n, testEnv)
			assert.False(t, strings.HasPrefix(strings.ToLower(key), strings.ToLower(i.NRPTKeyPrefix())),
				"cleanup of %s matches the default key %q", n, key)
		}
	}
}

func nrptKeys(i Instance) []string {
	return []string{i.NRPTKeyPrefix() + "Match-0", i.NRPTKeyPrefix() + "Match-12", i.NRPTKeyPrefix() + "ExemptLocal"}
}

func identifierSet(i Instance) []string {
	ids := []string{
		i.ServiceName(), i.ServiceDisplayName(), i.DaemonAddr(), i.JSONSocket(), i.StateDir(),
		i.LogFile(), i.PanicLogFile(), i.UpdaterTempDir(), i.UserDirName(), i.DebugBundlePattern(),
		i.ExportedDebugBundlePrefix(), i.KubeUser(), i.AdapterGUID(), i.InterfaceName(),
		i.NRPTKeyPrefix(), i.FirewallRuleName(), i.FirewallRuleNameV6(), i.SSHConfigFile(),
		i.UIUniqueID(), i.UIAppName(), i.QuickActionsEvent(), i.DebugTriggerEvent(),
	}
	if c := i.ToastActivatorCLSID(); c != "" {
		ids = append(ids, c)
	}
	return ids
}

// T-ID-05: UUIDv5 vectors of the identifier matrix.
func TestDerivedUUIDs(t *testing.T) {
	vectors := []struct {
		name, adapter, toast, msi string
	}{
		{"acme", "{930adb3f-6a74-541d-b49f-0166bb47c7a5}", "{5a3724b5-05f1-5ac3-9c29-1d659e422484}", "{5591c79a-cc85-5950-ade1-37bbbac4eff2}"},
		{"globex", "{a6d99cb5-b962-55f8-a433-705e9bdecab3}", "{c3d5f26a-b0a6-5c4d-bcde-c4ee39f0631e}", "{af29a36a-4d53-56d5-b302-938f316b97b6}"},
		{"work", "{ac400ff9-5e17-51ea-8325-48735885ac3a}", "{6dc35970-7893-52d2-ad74-eae475dfd451}", "{d2080a14-0751-579c-a860-9254ecfd4725}"},
	}
	def := newInstance(goosWindows, func(k string) string { return testEnv[k] }, DefaultName, "")
	for _, v := range vectors {
		i := windowsInstance(t, v.name, testEnv)
		assert.Equal(t, v.adapter, i.AdapterGUID(), "adapter GUID of %s", v.name)
		assert.Equal(t, v.toast, i.ToastActivatorCLSID(), "toast activator of %s", v.name)
		assert.Equal(t, v.msi, i.derivedUUID("msi-upgrade"), "MSI upgrade code of %s", v.name)
		assert.NotEqual(t, def.AdapterGUID(), i.AdapterGUID(), "never the default GUID")
	}
}

// T-NET-03: derived ports.
func TestDerivedPorts(t *testing.T) {
	ks := map[string]int{"acme": 16, "globex": 23, "work": 85}
	for name, k := range ks {
		i := windowsInstance(t, name, testEnv)
		assert.Equal(t, uint16(51820+k), i.WireGuardPort(), "WireGuard port of %s", name)
		assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", 9191+k), i.LocalMetricsAddr(), "metrics of %s", name)
		assert.Equal(t, fmt.Sprintf("localhost:%d", 6969+k), i.PprofAddr(), "pprof of %s", name)
		assert.Equal(t, uint16(1080+k), i.Socks5Port(), "SOCKS5 of %s", name)
	}
	for _, name := range []string{"a", "b", "z9", "abcdefghijkl", "x1y2", "q"} {
		p := windowsInstance(t, name, testEnv).WireGuardPort()
		assert.True(t, p >= 51821 && p <= 51920, "port %d of %s in range", p, name)
	}
}

// T-COEX-U1: role parsing falls back to secondary; the default ignores it.
func TestRoles(t *testing.T) {
	tests := []struct {
		in      string
		want    Role
		wantErr bool
	}{
		{"primary", RolePrimary, false},
		{"PRIMARY", RolePrimary, false},
		{"secondary", RoleSecondary, false},
		{"", RoleSecondary, false},
		{"main", RoleSecondary, true},
		{"primary ", RoleSecondary, true},
	}
	for _, tc := range tests {
		r, err := ParseRole(tc.in)
		assert.Equal(t, tc.want, r, "role of %q", tc.in)
		assert.Equal(t, tc.wantErr, err != nil, "error for %q: %v", tc.in, err)
	}

	def := newInstance(goosWindows, func(k string) string { return testEnv[k] }, DefaultName, "")
	assert.Equal(t, RolePrimary, def.WithRole(RoleSecondary).Role(), "default stays primary")

	named := windowsInstance(t, "acme", testEnv)
	assert.Equal(t, RoleSecondary, named.Role(), "named defaults to secondary")
	assert.Equal(t, RolePrimary, named.WithRole(RolePrimary).Role(), "named can be primary")
}

// SBS-SEC-03: a label from the installation record must name the installation.
func TestWithLabel(t *testing.T) {
	i := windowsInstance(t, "acme", testEnv)
	assert.Equal(t, "ACME", i.WithLabel("ACME").Label(), "matching label")
	assert.Equal(t, "acme", i.WithLabel("Other").Label(), "foreign label ignored")
	assert.Equal(t, "acme", i.WithLabel("").Label(), "empty label ignored")
	assert.Equal(t, "NetBird (AcMe)", i.WithLabel("AcMe").DisplayName(), "display name")
}
