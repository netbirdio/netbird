package dns

import "strings"

// filterNRPTRuleKeys returns the NRPT rule key names that start with prefix.
// Registry key names are case insensitive, so the match is too. Named
// installations' prefixes end in "-", which names cannot contain, so no prefix
// matches another installation's keys.
func filterNRPTRuleKeys(names []string, prefix string) []string {
	lowerPrefix := strings.ToLower(prefix)
	var keys []string
	for _, name := range names {
		if strings.HasPrefix(strings.ToLower(name), lowerPrefix) {
			keys = append(keys, name)
		}
	}
	return keys
}
