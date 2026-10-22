package geolocation

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

var countryCodeRegex = regexp.MustCompile("^[A-Z]{2}$")

// IsCountryCode reports whether code is an upper-case ISO 3166-1 alpha-2 country code.
func IsCountryCode(code string) bool {
	return countryCodeRegex.MatchString(code)
}

// countryRecord is the part of a database record needed to group networks by country.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// countryPrefixIndex maps country ISO codes to their merged prefixes. Walking the whole
// database takes seconds, so it is built once, on first use, and only when it is needed.
type countryPrefixIndex struct {
	once     sync.Once
	prefixes map[string][]netip.Prefix
	err      error
}

func (i *countryPrefixIndex) get(db *maxminddb.Reader) (map[string][]netip.Prefix, error) {
	i.once.Do(func() {
		i.prefixes, i.err = buildCountryPrefixes(db)
	})
	return i.prefixes, i.err
}

// CountryPrefixes returns the merged prefixes the database assigns to the country with the
// given ISO code, or none if the country is unknown.
func (gl *geolocationImpl) CountryPrefixes(countryISOCode string) ([]netip.Prefix, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

	if gl.db == nil {
		return nil, errDatabaseNotAvailable
	}

	index, err := gl.countries.get(gl.db)
	if err != nil {
		return nil, err
	}
	return slices.Clone(index[strings.ToUpper(countryISOCode)]), nil
}

func buildCountryPrefixes(db *maxminddb.Reader) (map[string][]netip.Prefix, error) {
	byCountry := make(map[string][]netip.Prefix)

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record countryRecord
		ipNet, err := networks.Network(&record)
		if err != nil {
			return nil, fmt.Errorf("decode network: %w", err)
		}
		if record.Country.ISOCode == "" {
			continue
		}

		addr, ok := netip.AddrFromSlice(ipNet.IP)
		// SkipAliasedNetworks returns IPv4 networks as 4 bytes, so a mapped address is an alias.
		if !ok || addr.Is4In6() {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		code := record.Country.ISOCode
		byCountry[code] = append(byCountry[code], netip.PrefixFrom(addr, ones).Masked())
	}
	if err := networks.Err(); err != nil {
		return nil, fmt.Errorf("walk networks: %w", err)
	}

	for code, prefixes := range byCountry {
		// The index lives as long as the database, so drop the capacity left over from merging.
		byCountry[code] = slices.Clone(mergePrefixes(prefixes))
	}
	return byCountry, nil
}

// mergePrefixes replaces each pair of sibling prefixes with their parent, repeatedly. The input
// must be sorted and free of overlaps, which holds for networks walked in database order.
func mergePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	merged := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		merged = append(merged, prefix)
		for len(merged) > 1 {
			last := len(merged) - 1
			parent, ok := siblingParent(merged[last-1], merged[last])
			if !ok {
				break
			}
			merged = append(merged[:last-1], parent)
		}
	}
	return merged
}

// siblingParent returns the parent of lower and upper when they are its two halves.
func siblingParent(lower, upper netip.Prefix) (netip.Prefix, bool) {
	if lower.Bits() == 0 || lower.Bits() != upper.Bits() || lower.Addr().Is4() != upper.Addr().Is4() {
		return netip.Prefix{}, false
	}

	parent := netip.PrefixFrom(lower.Addr(), lower.Bits()-1).Masked()
	if parent.Addr() != lower.Addr() || upper == lower || !parent.Contains(upper.Addr()) {
		return netip.Prefix{}, false
	}
	return parent, true
}
