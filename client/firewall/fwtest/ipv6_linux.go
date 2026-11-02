package fwtest

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const defaultDisableIPv6 = "/proc/sys/net/ipv6/conf/default/disable_ipv6"

// SkipWithoutIPv6 skips the test when an interface created now would not get IPv6. The name
// it asks about is random, so it never matches an interface the host already has: an
// interface that does not exist yet takes the host's default, as the test interface will.
// NewPeerNamespace needs that, since it gives the veth IPv6 addresses.
func SkipWithoutIPv6(t *testing.T) {
	t.Helper()

	suffix := make([]byte, 4)
	_, err := rand.Read(suffix)
	require.NoError(t, err, "generate interface name")

	if !firewall.HostHasIPv6("nbx" + hex.EncodeToString(suffix)) {
		t.Skip("host has no IPv6")
	}

	// HostHasIPv6 counts an interface that does not exist yet as enabled when "all" is, but a
	// new interface takes "default", which is what disables IPv6 on the veth.
	if b, err := os.ReadFile(defaultDisableIPv6); err == nil && strings.TrimSpace(string(b)) == "1" {
		t.Skip("new interfaces get IPv6 disabled by the host default")
	}
}

// SkipWithoutIPv6On skips the test when the named interface cannot receive IPv6, which is what
// the firewall decides on once the interface exists.
func SkipWithoutIPv6On(t *testing.T, ifaceName string) {
	t.Helper()

	if !firewall.HostHasIPv6(ifaceName) {
		t.Skipf("IPv6 is disabled on interface %s", ifaceName)
	}
}
