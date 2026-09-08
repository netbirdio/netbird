//go:build !ios && !android

package cmd

import (
	"fmt"
	"slices"
	"strings"

	"github.com/netbirdio/netbird/client/mdm"
)

// Principal kinds an --allow-group value resolves to. The kind:value form is
// the same one profile owners use, so a value in service.json or in a service
// unit says which namespace it belongs to instead of being a bare number that
// means one thing on Unix and another on Windows.
const (
	allowGroupKindGID = "gid"
	allowGroupKindSID = "sid"
)

// resolveAllowGroups turns configured group values into the typed principals
// the daemon enforces on its sockets, dropping empty entries and duplicates.
// Names are resolved through the platform's directory service, so an entry that
// does not resolve is an error: a restriction the daemon cannot evaluate must
// not become one that admits everybody. Values already in kind:value form are
// validated and passed through, which is the form an installed service hands to
// `service run`.
//
// Each value is split on commas, so one managed-configuration string listing
// several principals behaves like the repeated flag. Neither a Unix group name
// nor a Windows account name may contain a comma, so nothing is lost by it.
func resolveAllowGroups(values []string) ([]string, error) {
	var resolved []string
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}

			principal, err := resolveAllowGroup(entry)
			if err != nil {
				return nil, fmt.Errorf("resolve allowed group %q: %w", entry, err)
			}
			if !slices.Contains(resolved, principal) {
				resolved = append(resolved, principal)
			}
		}
	}

	if err := checkAllowGroupSet(resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

// daemonSocketPrincipals returns the principals the daemon restricts its
// sockets to, and the configuration that asked for them. An MDM policy
// overrides the install-time --allow-group in both directions, as the other
// MDM-overridable service flags do: a managed host can be restricted without a
// reinstall, and a managed empty value lifts a restriction the install set.
//
// A configured value that cannot be resolved is an error rather than an
// unrestricted socket. The daemon then does not serve at all, which is loud
// enough for an administrator to find and correct, where a silently ignored
// restriction would leave every local account reaching the daemon on a host
// meant to be locked down.
func daemonSocketPrincipals(policy *mdm.Policy) ([]string, string, error) {
	values, source := allowGroups, "--allow-group"
	if managed, ok := policy.GetStringSlice(mdm.KeyAllowGroups); ok {
		values, source = managed, "MDM policy "+mdm.KeyAllowGroups
	}

	resolved, err := resolveAllowGroups(values)
	if err != nil {
		return nil, source, fmt.Errorf("%s: %w", source, err)
	}
	return resolved, source, nil
}

// cutKind splits a value on the kind separator. ok is false when the value
// carries no kind, which is the case for a plain group or account name: neither
// a Unix group name nor a Windows account name may contain a colon, so the
// separator is unambiguous.
func cutKind(value string) (kind, rest string, ok bool) {
	kind, rest, ok = strings.Cut(value, ":")
	if !ok || rest == "" {
		return "", value, false
	}
	return kind, rest, true
}

// principalValue returns the value part of a kind:value principal of the
// expected kind.
func principalValue(principal, kind string) (string, bool) {
	got, value, ok := strings.Cut(principal, ":")
	if !ok || got != kind || value == "" {
		return "", false
	}
	return value, true
}
