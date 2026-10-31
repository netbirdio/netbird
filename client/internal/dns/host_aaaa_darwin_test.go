//go:build !ios

package dns

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const (
	testAAAAIfName    = "utun2301"
	testAAAAServiceID = netbirdServicePrefix + matchSuffix + "-0"
)

var (
	testAAAAResolver = netip.MustParseAddr("192.0.2.53")
	testAAAAV4       = netip.MustParsePrefix("100.64.0.10/16")
	testAAAAV6       = netip.MustParsePrefix("fd00:1234:5678::a/64")
)

// aaaaTestIface implements the parts of WGIface the AAAA overlay reads.
type aaaaTestIface struct {
	WGIface
	name string
	addr wgaddr.Address
}

func (i *aaaaTestIface) Name() string            { return i.name }
func (i *aaaaTestIface) Address() wgaddr.Address { return i.addr }

func testDualStackAddr() wgaddr.Address {
	return wgaddr.Address{
		IP:      testAAAAV4.Addr(),
		Network: testAAAAV4.Masked(),
		IPv6:    testAAAAV6.Addr(),
		IPv6Net: testAAAAV6.Masked(),
	}
}

func testAAAAOverlay() *aaaaOverlay {
	return &aaaaOverlay{ifName: testAAAAIfName, v4: testAAAAV4, v6: testAAAAV6}
}

func TestServiceIDFromDNSKey(t *testing.T) {
	tests := []struct {
		key    string
		wantID string
		wantOK bool
	}{
		{"State:/Network/Service/NetBird-Match-0/DNS", "NetBird-Match-0", true},
		{"State:/Network/Service/NetBird-Search-3/DNS", "NetBird-Search-3", true},
		{"State:/Network/Service/NetBird-Local/DNS", "NetBird-Local", true},
		{"State:/Network/Service/NetBird-Match-0/IPv4", "", false},
		{"State:/Network/Service/0F2A3B4C-0000-0000-0000-000000000000/DNS", "", false},
		{"State:/Network/Global/DNS", "", false},
		{"State:/Network/Service//DNS", "", false},
		{"State:/Network/Service/NetBird-a/b/DNS", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			id, ok := serviceIDFromDNSKey(tt.key)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func TestServiceIDFromDNSKeyMatchesPublishedKeys(t *testing.T) {
	for _, key := range []string{
		getKeyWithInput(netbirdDNSStateKeyFormat, localSuffix),
		getKeyWithInput(netbirdDNSStateKeyFormat, searchSuffix),
	} {
		_, ok := serviceIDFromDNSKey(key)
		assert.True(t, ok, key)
	}

	id, ok := serviceIDFromDNSKey(serviceEntityKey(testAAAAServiceID, entityDNS))
	assert.True(t, ok)
	assert.Equal(t, testAAAAServiceID, id)
}

func TestAAAAOverlayFor(t *testing.T) {
	newConfigurator := func(addr wgaddr.Address) *systemConfigurator {
		return &systemConfigurator{wgInterface: &aaaaTestIface{name: testAAAAIfName, addr: addr}}
	}

	t.Run("no interface", func(t *testing.T) {
		s := &systemConfigurator{}
		assert.Nil(t, s.aaaaOverlayFor(testAAAAResolver))
	})

	t.Run("overlay without IPv6", func(t *testing.T) {
		addr := testDualStackAddr()
		addr.ClearIPv6()
		assert.Nil(t, newConfigurator(addr).aaaaOverlayFor(testAAAAResolver))
	})

	t.Run("loopback resolver", func(t *testing.T) {
		assert.Nil(t, newConfigurator(testDualStackAddr()).aaaaOverlayFor(netip.MustParseAddr("127.0.0.1")))
	})

	t.Run("invalid resolver", func(t *testing.T) {
		assert.Nil(t, newConfigurator(testDualStackAddr()).aaaaOverlayFor(netip.Addr{}))
	})

	t.Run("disabled by env", func(t *testing.T) {
		t.Setenv(envDisableDarwinAAAA, "true")
		assert.Nil(t, newConfigurator(testDualStackAddr()).aaaaOverlayFor(testAAAAResolver))
	})

	t.Run("dual stack overlay", func(t *testing.T) {
		o := newConfigurator(testDualStackAddr()).aaaaOverlayFor(testAAAAResolver)
		require.NotNil(t, o)
		assert.Equal(t, testAAAAOverlay(), o)
	})
}

func TestBuildAddDNSStateCommandsWithOverlay(t *testing.T) {
	key := serviceEntityKey(testAAAAServiceID, entityDNS)
	got := buildAddDNSStateCommands(key, "example.internal corp.example", testAAAAResolver, DefaultPort, false, testAAAAOverlay())

	// Expected output is spelled out to catch typos in the scutil keys.
	want := "d.init\n" +
		"d.add PrimaryRank Never\n" +
		"set State:/Network/Service/NetBird-Match-0\n" +
		"d.init\n" +
		"d.add InterfaceName utun2301\n" +
		"d.add Addresses * 100.64.0.10\n" +
		"d.add SubnetMasks * 255.255.0.0\n" +
		"d.add Router 100.64.0.10\n" +
		"set State:/Network/Service/NetBird-Match-0/IPv4\n" +
		"d.init\n" +
		"d.add InterfaceName utun2301\n" +
		"d.add Addresses * fd00:1234:5678::a\n" +
		"d.add PrefixLength * # 64\n" +
		"d.add Router fd00:1234:5678::a\n" +
		"set State:/Network/Service/NetBird-Match-0/IPv6\n"
	require.True(t, strings.HasPrefix(got, want), "overlay entities must precede the resolver, got:\n%s", got)

	dns := strings.TrimPrefix(got, want)
	assert.Contains(t, dns, "d.add SupplementalMatchDomains * example.internal corp.example\n")
	assert.Contains(t, dns, "d.add ServerAddresses * 192.0.2.53\n")
	assert.Contains(t, dns, "d.add ConfirmedServiceID NetBird-Match-0\n")
	assert.True(t, strings.HasSuffix(dns, "set "+key+"\n"))
}

func TestBuildAddDNSStateCommandsWithoutOverlay(t *testing.T) {
	key := serviceEntityKey(testAAAAServiceID, entityDNS)
	got := buildAddDNSStateCommands(key, "example.internal", testAAAAResolver, DefaultPort, false, nil)

	assert.NotContains(t, got, keyPrimaryRank)
	assert.NotContains(t, got, serviceEntityKey(testAAAAServiceID, entityIPv4))
	assert.NotContains(t, got, serviceEntityKey(testAAAAServiceID, entityIPv6))
	assert.NotContains(t, got, keyConfirmedServiceID)
	assert.Contains(t, got, "d.add ServerAddresses * 192.0.2.53\n")
}

func TestBuildAAAARemoveCommands(t *testing.T) {
	assert.Equal(t,
		"remove State:/Network/Service/NetBird-Match-0/IPv4\n"+
			"remove State:/Network/Service/NetBird-Match-0/IPv6\n"+
			"remove State:/Network/Service/NetBird-Match-0\n",
		buildAAAARemoveCommands(testAAAAServiceID))
}
