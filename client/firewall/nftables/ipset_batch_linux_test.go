//go:build !android && privileged

package nftables

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
)

var setBatchSizeCases = []struct {
	name  string
	v6    bool
	count int
}{
	// The IPv4 case proves the read-back works for a set of this size,
	// so an IPv6 mismatch cannot be blamed on the element dump.
	{name: "IPv4 1200 prefixes control", count: 1200},
	{name: "IPv6 1023 prefixes", v6: true, count: 1023},
	{name: "IPv6 1024 prefixes", v6: true, count: 1024},
	{name: "IPv6 1200 prefixes", v6: true, count: 1200},
	{name: "IPv6 2500 prefixes", v6: true, count: 2500},
}

func TestNftablesCreateIpSetBatchSize(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	for _, tt := range setBatchSizeCases {
		t.Run(tt.name, func(t *testing.T) {
			r := newBatchTestFamily(t, tt.v6)

			sources := spacedHostPrefixes(tt.v6, tt.count)
			setName := firewall.NewPrefixSet(sources).HashedName()

			set, err := r.createIpSet(setName, setInput{prefixes: sources})
			require.NoError(t, err, "set creation must not be rejected")
			require.NotNil(t, set, "created set must be returned")
			commitQueuedIpSet(t, r)

			assert.Equal(t, tt.count, kernelSetPrefixCount(t, r, setName),
				"kernel set must hold every prefix that was requested")
		})
	}
}

func TestNftablesUpdateSetBatchSize(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	for _, tt := range setBatchSizeCases {
		t.Run(tt.name, func(t *testing.T) {
			r := newBatchTestFamily(t, tt.v6)

			sources := spacedHostPrefixes(tt.v6, tt.count)
			set := firewall.NewPrefixSet(sources)

			created, err := r.createIpSet(set.HashedName(), setInput{})
			require.NoError(t, err, "empty set creation must succeed")
			require.NotNil(t, created, "created set must be returned")
			commitQueuedIpSet(t, r)

			require.NoError(t, r.UpdateSet(set, sources), "set update must not be rejected")

			assert.Equal(t, tt.count, kernelSetPrefixCount(t, r, set.HashedName()),
				"kernel set must hold every prefix that was added")
		})
	}
}

func newBatchTestFamily(t *testing.T, v6 bool) *family {
	t.Helper()

	createTable, deleteTable := createWorkTable, deleteWorkTable
	if v6 {
		createTable, deleteTable = createWorkTableIPv6, deleteWorkTableIPv6
	}

	workTable, err := createTable()
	require.NoError(t, err, "work table must be created")
	t.Cleanup(deleteTable)

	r := newFamily(workTable, ifaceMock, iface.DefaultMTU)
	require.NoError(t, r.init(workTable), "family init must succeed")
	t.Cleanup(func() {
		require.NoError(t, r.Reset(), "family reset must succeed")
	})

	return r
}

func kernelSetPrefixCount(t *testing.T, r *family, setName string) int {
	t.Helper()

	fetchedSet, err := r.conn.GetSetByName(r.workTable, setName)
	require.NoError(t, err, "set must exist in the kernel")

	elements, err := r.conn.GetSetElements(fetchedSet)
	require.NoError(t, err, "set elements must be readable")

	count := 0
	for _, elem := range elements {
		if !elem.IntervalEnd {
			count++
		}
	}
	return count
}

func spacedHostPrefixes(v6 bool, count int) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, count)
	for i := range count {
		// Two addresses apart, so no two intervals touch and each prefix
		// stays a separate element pair in the kernel.
		host := uint32(i+1) * 2
		if v6 {
			addr := [16]byte{0: 0xfd}
			binary.BigEndian.PutUint32(addr[12:], host)
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(addr), 128))
			continue
		}
		var addr [4]byte
		binary.BigEndian.PutUint32(addr[:], 0x0a000000+host)
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(addr), 32))
	}
	return prefixes
}
