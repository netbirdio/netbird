//go:build !ios && !android

package cmd

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/mdm"
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
			if value := principal.String(); !slices.Contains(resolved, value) {
				resolved = append(resolved, value)
			}
		}
	}

	if err := checkAllowGroupSet(resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

// bootResolveTimeout bounds the group resolution the daemon does while
// starting. A value already in kind:value form resolves without a lookup, so
// this only bites on a name, which getent, NSS or LSA may answer from a
// directory service that is slow or unreachable.
const bootResolveTimeout = 5 * time.Second

// resolveAllowGroupsBounded resolves the configured groups without letting a
// directory lookup hold up the daemon's start indefinitely.
//
// The lookup runs on its own goroutine because the platform calls underneath it
// take no context: on timeout the daemon stops waiting and refuses to serve,
// while the goroutine finishes into a buffered channel nobody reads. Refusing
// is the same answer a failed resolution gets, since a restriction that cannot
// be evaluated must not become a socket open to everybody.
func resolveAllowGroupsBounded(values []string) ([]string, error) {
	return resolveAllowGroupsWithin(values, bootResolveTimeout, resolveAllowGroups)
}

// resolveAllowGroupsWithin is resolveAllowGroupsBounded with the timeout and
// the resolver supplied, so a test can drive the deadline without waiting on
// one or needing a directory service that hangs.
func resolveAllowGroupsWithin(values []string, timeout time.Duration, resolve func([]string) ([]string, error)) ([]string, error) {
	type outcome struct {
		principals []string
		err        error
	}

	done := make(chan outcome, 1)
	go func() {
		principals, err := resolve(values)
		done <- outcome{principals, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-done:
		return res.principals, res.err
	case <-timer.C:
		return nil, fmt.Errorf("resolving the allowed groups took longer than %s: configure them as resolved principals (%s:<id> or %s:<SID>) so the daemon needs no directory lookup while starting",
			timeout, ipcauth.KindGID, ipcauth.KindSID)
	}
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

	if policy.HasKey(mdm.KeyAllowGroups) {
		source = "MDM policy " + mdm.KeyAllowGroups
		managed, ok := policy.GetStringSlice(mdm.KeyAllowGroups)
		if !ok {
			// The key is managed but holds something that is not a list of
			// strings. Falling back to the install-time value, or to no
			// restriction at all, would apply an access rule the administrator
			// did not write.
			return nil, source, fmt.Errorf("%s: managed value is not a list of principals", source)
		}
		values = managed
	}

	resolved, err := resolveAllowGroupsBounded(values)
	if err != nil {
		return nil, source, fmt.Errorf("%s: %w", source, err)
	}
	return resolved, source, nil
}

// typedPrincipal parses a value that carries an explicit kind, as
// ipcauth.Principal renders it. ok is false when the value carries no kind at
// all, which is the case for a plain group or account name: neither a Unix
// group name nor a Windows account name may contain a colon, so the separator
// is unambiguous. A value that has a kind the shared type does not know is an
// error rather than a name to look up.
func typedPrincipal(value string, want ipcauth.PrincipalKind) (ipcauth.Principal, bool, error) {
	if !strings.Contains(value, ":") {
		return ipcauth.Principal{}, false, nil
	}

	principal, ok := ipcauth.ParsePrincipal(value)
	if !ok {
		return ipcauth.Principal{}, false, fmt.Errorf("not a principal, use a name or %s:<value>", want)
	}
	if principal.Kind != want {
		return ipcauth.Principal{}, false, fmt.Errorf("unsupported principal kind %q on this platform, use a name or %s:<value>", principal.Kind, want)
	}
	return principal, true, nil
}

// principalOfKind parses a stored principal that must be of the given kind.
func principalOfKind(value string, want ipcauth.PrincipalKind) (ipcauth.Principal, error) {
	principal, ok := ipcauth.ParsePrincipal(value)
	if !ok || principal.Kind != want {
		return ipcauth.Principal{}, fmt.Errorf("not a %s principal: %q", want, value)
	}
	return principal, nil
}
