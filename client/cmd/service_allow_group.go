//go:build !ios && !android

package cmd

import (
	"fmt"
	"slices"
	"strings"
)

// Principal kinds an --allow-group value resolves to. The kind:value form is
// the same one profile owners use, so a value in service.json or in a service
// unit says which namespace it belongs to instead of being a bare number that
// means one thing on Unix and another on Windows.
const (
	allowGroupKindGID = "gid"
	allowGroupKindSID = "sid"
)

// resolveAllowGroups turns the values given on --allow-group into the typed
// principals the daemon enforces on its sockets, dropping empty entries and
// duplicates. Names are resolved through the platform's directory service, so
// an entry that does not resolve is an error: a restriction the daemon cannot
// evaluate must not become one that admits everybody. Values already in
// kind:value form are validated and passed through, which is the form an
// installed service hands to `service run`.
func resolveAllowGroups(values []string) ([]string, error) {
	var resolved []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		principal, err := resolveAllowGroup(value)
		if err != nil {
			return nil, fmt.Errorf("resolve --allow-group %q: %w", value, err)
		}
		if !slices.Contains(resolved, principal) {
			resolved = append(resolved, principal)
		}
	}

	if err := checkAllowGroupSet(resolved); err != nil {
		return nil, err
	}
	return resolved, nil
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
