package recordwriter

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// apexCandidates returns the candidate apex zones for an FQDN, ordered
// longest-first. Used by record writers to find which zone in the user's
// account owns the FQDN they want to write a CNAME at.
//
// Examples:
//
//	"*.app.example.com" → ["app.example.com", "example.com"]
//	"app.example.com"   → ["app.example.com", "example.com"]
//	"example.com"       → ["example.com"]
//	"*.example.co.uk"   → ["example.co.uk"]
//
// The wildcard "*." prefix is stripped before candidate generation. The
// public-suffix list is consulted so we don't generate impossible
// candidates like "co.uk" — those return only "example.co.uk".
//
// Longest-first ordering matters: a user with both example.com and
// example.com.au registered must match example.com when the FQDN is
// *.api.example.com. Without longest-first, a shorter accidental match
// would route the write to the wrong zone.
func apexCandidates(fqdn string) []string {
	host := strings.TrimPrefix(fqdn, "*.")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil
	}

	// Determine the eTLD+1 (effective top-level domain plus one label).
	// We never generate candidates shorter than this.
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// If publicsuffix can't classify (e.g., host is a single label
		// or contains an unknown TLD), fall back to using the whole host.
		return []string{host}
	}

	var out []string
	current := host
	for {
		out = append(out, current)
		if current == etldPlusOne {
			break
		}
		// Strip the leftmost label.
		i := strings.Index(current, ".")
		if i < 0 {
			break
		}
		current = current[i+1:]
		if current == "" {
			break
		}
	}
	return out
}
