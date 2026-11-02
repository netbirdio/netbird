package manager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowUnfilteredIPv6(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "unset keeps the deny", value: "", want: false},
		{name: "true", value: "true", want: true},
		{name: "one", value: "1", want: true},
		{name: "false", value: "false", want: false},
		{name: "zero", value: "0", want: false},
		{name: "not a boolean keeps the deny", value: "yes please", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvAllowUnfilteredIPv6, tt.value)
			if tt.value == "" {
				require.NoError(t, os.Unsetenv(EnvAllowUnfilteredIPv6))
			}
			assert.Equal(t, tt.want, AllowUnfilteredIPv6())
		})
	}
}

func TestHostHasIPv6PerInterface(t *testing.T) {
	setup := func(t *testing.T, all, def string, ifaces map[string]string) (ifInet6, confDir string) {
		t.Helper()
		dir := t.TempDir()
		ifInet6 = filepath.Join(dir, "if_inet6")
		require.NoError(t, os.WriteFile(ifInet6, nil, 0o600))
		confDir = filepath.Join(dir, "conf")
		write := func(name, value string) {
			require.NoError(t, os.MkdirAll(filepath.Join(confDir, name), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(confDir, name, disableIPv6Entry), []byte(value+"\n"), 0o600))
		}
		write("all", all)
		write("default", def)
		for name, value := range ifaces {
			write(name, value)
		}
		return ifInet6, confDir
	}

	tests := []struct {
		name   string
		all    string
		def    string
		ifaces map[string]string
		iface  string
		want   bool
	}{
		{name: "enabled by default", all: "0", def: "0", iface: "wt0", want: true},
		{name: "default enabled alone", all: "1", def: "0", iface: "wt0", want: true},
		{name: "all enabled alone", all: "0", def: "1", iface: "wt0", want: true},
		{name: "disabled everywhere", all: "1", def: "1", ifaces: map[string]string{"wt0": "1"}, iface: "wt0", want: false},
		{name: "interface that does not exist yet inherits the default", all: "1", def: "1", iface: "wt0", want: false},
		{name: "existing interface re-enabled after the global disable", all: "1", def: "1", ifaces: map[string]string{"wt0": "0"}, iface: "wt0", want: true},
		{name: "another interface enabled does not count", all: "1", def: "1", ifaces: map[string]string{"wt0": "1", "eth0": "0"}, iface: "wt0", want: false},
		{name: "unexpected value counts as enabled", all: "1", def: "1", ifaces: map[string]string{"wt0": "x"}, iface: "wt0", want: true},
		{name: "empty name counts as enabled", all: "1", def: "1", iface: "", want: true},
		{name: "path in name counts as enabled", all: "1", def: "1", iface: "../all", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifInet6, confDir := setup(t, tt.all, tt.def, tt.ifaces)
			assert.Equal(t, tt.want, hostHasIPv6(ifInet6, confDir, tt.iface))
		})
	}

	t.Run("no kernel IPv6 support", func(t *testing.T) {
		_, confDir := setup(t, "0", "0", nil)
		assert.False(t, hostHasIPv6(filepath.Join(t.TempDir(), "missing"), confDir, "wt0"))
	})

	t.Run("unreadable interface entry counts as enabled", func(t *testing.T) {
		ifInet6, confDir := setup(t, "1", "1", nil)
		// A directory where the file belongs: reading it fails with something other than not-exist.
		require.NoError(t, os.MkdirAll(filepath.Join(confDir, "wt0", disableIPv6Entry), 0o700))
		assert.True(t, hostHasIPv6(ifInet6, confDir, "wt0"))
	})
}
