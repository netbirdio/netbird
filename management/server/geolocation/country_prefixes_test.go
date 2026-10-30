package geolocation

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergePrefixes(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		expected []string
	}{
		{
			name:     "empty",
			prefixes: nil,
			expected: []string{},
		},
		{
			name:     "siblings merge into their parent",
			prefixes: []string{"10.0.0.0/25", "10.0.0.128/25"},
			expected: []string{"10.0.0.0/24"},
		},
		{
			name:     "merges cascade up the tree",
			prefixes: []string{"10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/25"},
			expected: []string{"10.0.0.0/23"},
		},
		{
			// 10.0.1.0/24 and 10.0.2.0/24 are adjacent but belong to different /23s.
			name:     "adjacent non-siblings stay apart",
			prefixes: []string{"10.0.1.0/24", "10.0.2.0/24"},
			expected: []string{"10.0.1.0/24", "10.0.2.0/24"},
		},
		{
			name:     "a gap prevents the merge",
			prefixes: []string{"10.0.0.0/25", "10.0.1.0/25"},
			expected: []string{"10.0.0.0/25", "10.0.1.0/25"},
		},
		{
			name:     "different lengths do not merge",
			prefixes: []string{"10.0.0.0/25", "10.0.0.128/26"},
			expected: []string{"10.0.0.0/25", "10.0.0.128/26"},
		},
		{
			name:     "ipv6 siblings merge",
			prefixes: []string{"2001:db8::/33", "2001:db8:8000::/33"},
			expected: []string{"2001:db8::/32"},
		},
		{
			name:     "families are merged separately",
			prefixes: []string{"10.0.0.0/25", "10.0.0.128/25", "2001:db8::/33", "2001:db8:8000::/33"},
			expected: []string{"10.0.0.0/24", "2001:db8::/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes := make([]netip.Prefix, 0, len(tt.prefixes))
			for _, p := range tt.prefixes {
				prefixes = append(prefixes, netip.MustParsePrefix(p))
			}

			merged := make([]string, 0)
			for _, p := range mergePrefixes(prefixes) {
				merged = append(merged, p.String())
			}
			assert.Equal(t, tt.expected, merged, "merged prefixes should match")
		})
	}
}

func TestGeoLite_CountryPrefixes(t *testing.T) {
	db, err := openDB(mmdbPath)
	require.NoError(t, err)

	geo := &geolocationImpl{db: db, stopCh: make(chan struct{})}
	t.Cleanup(func() {
		assert.NoError(t, geo.Stop())
	})

	t.Run("known country, case insensitive", func(t *testing.T) {
		prefixes, err := geo.CountryPrefixes("se")
		require.NoError(t, err)

		var v4 []netip.Prefix
		for _, p := range prefixes {
			if p.Addr().Is4() {
				v4 = append(v4, p)
			}
		}
		expected := []netip.Prefix{
			netip.MustParsePrefix("89.160.20.112/28"),
			netip.MustParsePrefix("89.160.20.128/25"),
		}
		assert.Equal(t, expected, v4, "IPv4 prefixes of SE in the test database")
		assert.Greater(t, len(prefixes), len(v4), "SE should also have IPv6 prefixes")
	})

	t.Run("unknown country", func(t *testing.T) {
		prefixes, err := geo.CountryPrefixes("ZZ")
		require.NoError(t, err)
		assert.Empty(t, prefixes, "an unknown country should have no prefixes")
	})

	t.Run("callers get their own copy", func(t *testing.T) {
		first, err := geo.CountryPrefixes("SE")
		require.NoError(t, err)
		require.NotEmpty(t, first)
		first[0] = netip.MustParsePrefix("192.0.2.0/24")

		second, err := geo.CountryPrefixes("SE")
		require.NoError(t, err)
		assert.Equal(t, netip.MustParsePrefix("89.160.20.112/28"), second[0], "the index must not change")
	})
}

func TestGeoLite_CountryPrefixesStopped(t *testing.T) {
	db, err := openDB(mmdbPath)
	require.NoError(t, err)

	geo := &geolocationImpl{db: db, stopCh: make(chan struct{})}
	require.NoError(t, geo.Stop())

	_, err = geo.CountryPrefixes("SE")
	assert.ErrorIs(t, err, errDatabaseNotAvailable)
}
