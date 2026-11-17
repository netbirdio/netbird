package anonymize

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLeveledAnonymizer(level Level) *Anonymizer {
	a := NewAnonymizer(DefaultAddresses())
	a.SetLevel(level)
	return a
}

// TestAnonymizeDomainReverseZone covers reverse zones going through the address
// rules instead of the domain ones, so a zone stays a zone and an address that
// is preserved keeps the zone that names it.
func TestAnonymizeDomainReverseZone(t *testing.T) {
	// 100.64.0.0/10 is the overlay range, which is CGNAT: preserved at the
	// default level and replaced from the internal pool at the strict one
	const overlayZone = "64.100.in-addr.arpa"

	t.Run("overlay zone preserved at the default level", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)
		assert.Equal(t, overlayZone, a.AnonymizeDomain(overlayZone), "should keep the zone of a preserved address")
	})

	t.Run("private zone preserved at the default level", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)
		assert.Equal(t, "168.192.in-addr.arpa", a.AnonymizeDomain("168.192.in-addr.arpa"), "should keep the zone of a private address")
	})

	t.Run("overlay zone replaced at the strict level", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelStrict)

		got := a.AnonymizeDomain(overlayZone)
		require.True(t, strings.HasSuffix(got, reverseZoneSuffixV4), "should stay a reverse zone, got %q", got)
		assert.NotEqual(t, overlayZone, got, "should replace the encoded prefix")
		assert.Len(t, strings.Split(strings.TrimSuffix(got, reverseZoneSuffixV4), "."), 2,
			"should keep the label count, got %q", got)
	})

	t.Run("public zone replaced at the default level", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)

		got := a.AnonymizeDomain("113.0.203.in-addr.arpa")
		require.True(t, strings.HasSuffix(got, reverseZoneSuffixV4), "should stay a reverse zone, got %q", got)
		assert.NotEqual(t, "113.0.203.in-addr.arpa", got, "should replace a public prefix")
	})

	t.Run("zone of an address keeps that address mapping", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)

		anonymizedAddr := a.AnonymizeIPString("203.0.113.7")
		got := a.AnonymizeDomain("7.113.0.203.in-addr.arpa")

		octets := strings.Split(anonymizedAddr, ".")
		want := octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0] + reverseZoneSuffixV4
		assert.Equal(t, want, got, "should name the same replacement as the address itself")
	})

	t.Run("ipv6 nibble labels stay single digits", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)

		zone := "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0" + reverseZoneSuffixV6
		got := a.AnonymizeDomain(zone)

		require.True(t, strings.HasSuffix(got, reverseZoneSuffixV6), "should stay a reverse zone, got %q", got)
		labels := strings.Split(strings.TrimSuffix(got, reverseZoneSuffixV6), ".")
		assert.Len(t, labels, 28, "should keep every nibble label, got %q", got)
		for _, label := range labels {
			assert.Len(t, label, 1, "nibble label %q should stay a single digit", label)
		}
	})

	t.Run("trailing dot is kept", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)
		assert.Equal(t, "64.100.in-addr.arpa.", a.AnonymizeDomain("64.100.in-addr.arpa."), "should keep the trailing dot")
	})

	t.Run("a domain that only looks like a zone is anonymized as a domain", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)

		got := a.AnonymizeDomain("not-a-zone.in-addr.arpa")
		assert.NotContains(t, got, "in-addr.arpa", "should fall back to domain anonymization")
	})
}

// TestAnonymizeStringReverseZone verifies that a zone inside free text, such as
// a DNS log line, is not chewed up by the address passes. The IPv4 pattern
// matches any run of dotted digits, which a reverse zone is made of.
func TestAnonymizeStringReverseZone(t *testing.T) {
	t.Run("ipv6 zone survives the address passes", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)

		zone := "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0" + reverseZoneSuffixV6
		got := a.AnonymizeString("question: domain=" + zone + " type=PTR")

		assert.Contains(t, got, "type=PTR", "should keep the rest of the line")
		assert.NotContains(t, got, "198.51.100", "should not rewrite nibble labels as an address")

		labels := strings.Split(strings.TrimSuffix(strings.TrimPrefix(got, "question: domain="), reverseZoneSuffixV6+" type=PTR"), ".")
		assert.Len(t, labels, 28, "should keep every nibble label, got %q", got)
	})

	t.Run("preserved ipv4 zone is untouched", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)

		line := "reverse zone 64.100.in-addr.arpa registered"
		assert.Equal(t, line, a.AnonymizeString(line), "should keep the zone of a preserved address")
	})

	t.Run("public ipv4 zone is replaced consistently", func(t *testing.T) {
		a := newLeveledAnonymizer(LevelDefault)

		got := a.AnonymizeString("zone 113.0.203.in-addr.arpa and address 203.0.113.7")
		assert.NotContains(t, got, "113.0.203.in-addr.arpa", "should replace the zone")
		assert.NotContains(t, got, "203.0.113.7", "should replace the address")
		assert.Contains(t, got, reverseZoneSuffixV4, "should keep the zone suffix")
	})
}

func TestParseReverseZone(t *testing.T) {
	tests := []struct {
		name   string
		zone   string
		addr   string
		labels int
	}{
		{name: "v4 two labels", zone: "0.100" + reverseZoneSuffixV4, addr: "100.0.0.0", labels: 2},
		{name: "v4 three labels", zone: "1.168.192" + reverseZoneSuffixV4, addr: "192.168.1.0", labels: 3},
		{name: "v4 full address", zone: "7.113.0.203" + reverseZoneSuffixV4, addr: "203.0.113.7", labels: 4},
		{
			name:   "v6 prefix",
			zone:   "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0" + reverseZoneSuffixV6,
			addr:   "2::",
			labels: 28,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, labels, suffix, ok := parseReverseZone(tc.zone)
			require.True(t, ok, "should decode the reverse zone")
			assert.Equal(t, tc.addr, addr.String(), "should decode to the encoded prefix")
			assert.Equal(t, tc.labels, labels, "should count the labels")
			assert.Equal(t, tc.zone, reverseZoneName(addr, labels)+suffix, "should re-encode to the original zone")
		})
	}
}

func TestParseReverseZoneRejectsNonZones(t *testing.T) {
	tests := []string{
		"example.com",
		"in-addr.arpa",
		"x.100" + reverseZoneSuffixV4,
		"256" + reverseZoneSuffixV4,
		"1.2.3.4.5" + reverseZoneSuffixV4,
		"ab" + reverseZoneSuffixV6,
		"g" + reverseZoneSuffixV6,
	}

	for _, zone := range tests {
		t.Run(zone, func(t *testing.T) {
			_, _, _, ok := parseReverseZone(zone)
			assert.False(t, ok, "should reject %q", zone)
		})
	}
}
