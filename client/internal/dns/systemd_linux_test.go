//go:build !android

package dns

import (
	"net/netip"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The dbus signatures are the contract with resolved: SetDNS has no port field,
// so a resolver on a fallback port can only be advertised through SetDNSEx.
func TestSystemdDNSInputSignatures(t *testing.T) {
	assert.Equal(t, "(iay)", dbus.SignatureOf(systemdDbusDNSInput{}).String())
	assert.Equal(t, "(iayqs)", dbus.SignatureOf(systemdDbusDNSInputEx{}).String())
}

func TestSystemdDNSServerMethod(t *testing.T) {
	serverIP := netip.MustParseAddr("100.66.100.1")
	serverIPv6 := netip.MustParseAddr("fd00::1")

	t.Run("default port uses SetDNS", func(t *testing.T) {
		c := &systemdDbusConfigurator{supportsDNSEx: true}

		method, input := c.dnsServerMethod(HostDNSConfig{ServerIP: serverIP, ServerPort: DefaultPort})

		assert.Equal(t, systemdDbusSetDNSMethodSuffix, method)
		in, ok := input.([]systemdDbusDNSInput)
		require.True(t, ok, "input type %T", input)
		require.Len(t, in, 1)
		assert.Equal(t, int32(unix.AF_INET), in[0].Family)
		assert.Equal(t, serverIP.AsSlice(), in[0].Address)
	})

	t.Run("fallback port carries the port through SetDNSEx", func(t *testing.T) {
		c := &systemdDbusConfigurator{supportsDNSEx: true}

		method, input := c.dnsServerMethod(HostDNSConfig{ServerIP: serverIP, ServerPort: 5053})

		assert.Equal(t, systemdDbusSetDNSExMethodSuffix, method)
		in, ok := input.([]systemdDbusDNSInputEx)
		require.True(t, ok, "input type %T", input)
		require.Len(t, in, 1)
		assert.Equal(t, int32(unix.AF_INET), in[0].Family)
		assert.Equal(t, serverIP.AsSlice(), in[0].Address)
		assert.Equal(t, uint16(5053), in[0].Port)
		assert.Empty(t, in[0].Name)
	})

	t.Run("v6 resolver reports the v6 family", func(t *testing.T) {
		c := &systemdDbusConfigurator{supportsDNSEx: true}

		_, input := c.dnsServerMethod(HostDNSConfig{ServerIP: serverIPv6, ServerPort: 5053})

		in, ok := input.([]systemdDbusDNSInputEx)
		require.True(t, ok, "input type %T", input)
		require.Len(t, in, 1)
		assert.Equal(t, int32(unix.AF_INET6), in[0].Family)
	})

	// Without SetDNSEx there is nothing to fall back to but the portless call.
	// supportCustomPort reports false so the caller keeps primary DNS off the
	// link instead of pointing it at a port resolved will not use.
	t.Run("no SetDNSEx support falls back to SetDNS", func(t *testing.T) {
		c := &systemdDbusConfigurator{supportsDNSEx: false}

		method, input := c.dnsServerMethod(HostDNSConfig{ServerIP: serverIP, ServerPort: 5053})

		assert.Equal(t, systemdDbusSetDNSMethodSuffix, method)
		assert.IsType(t, []systemdDbusDNSInput{}, input)
		assert.False(t, c.supportCustomPort())
	})
}
