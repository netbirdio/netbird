package dns

import "strings"

// secondaryHostConfig removes what a secondary installation must not take
// over: the catch-all, which on Windows means the "." NRPT rule, the .local
// exemption and the adapter NameServer. Two catch-all rules tie and Windows
// picks one arbitrarily. Match domains stay. It reports whether a catch-all was
// dropped.
func secondaryHostConfig(config HostDNSConfig) (HostDNSConfig, bool) {
	dropped := config.RouteAll
	config.RouteAll = false

	domains := make([]DomainConfig, 0, len(config.Domains))
	for _, d := range config.Domains {
		if strings.TrimSuffix(d.Domain, ".") == "" && !d.Disabled {
			dropped = true
			continue
		}
		domains = append(domains, d)
	}
	config.Domains = domains
	return config, dropped
}

// isForeignNRPTKey reports whether an NRPT key belongs to another NetBird
// installation: its name starts with "NetBird-" or "NetBird_", case
// insensitively, but not with ownPrefix.
func isForeignNRPTKey(name, ownPrefix string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, strings.ToLower(ownPrefix)) {
		return false
	}
	return strings.HasPrefix(lower, "netbird-") || strings.HasPrefix(lower, "netbird_")
}

// dropClaimedNamespaces removes the NRPT namespaces another installation
// already claims. The tie-break between identical namespaces is undocumented, so
// a secondary skips them and reports them instead of competing.
func dropClaimedNamespaces(namespaces []string, claimed map[string]struct{}) (kept, skipped []string) {
	for _, ns := range namespaces {
		if _, ok := claimed[strings.ToLower(ns)]; ok {
			skipped = append(skipped, ns)
			continue
		}
		kept = append(kept, ns)
	}
	return kept, skipped
}

// namespaceSkipReporter is implemented by a host manager that skipped match
// domains another installation claims, so the server can report them.
type namespaceSkipReporter interface {
	skippedNamespaces() []string
}
