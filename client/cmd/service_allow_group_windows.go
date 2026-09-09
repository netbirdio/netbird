//go:build windows

package cmd

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// resolveAllowGroup resolves one --allow-group value to a "sid:<SID>"
// principal. A value already in SID form, with or without the prefix, is
// validated and canonicalised; anything else is an account name resolved with
// LookupAccountName, which goes through LSA and so resolves domain groups on a
// joined machine as readily as local ones.
//
// Both a group and a user account are accepted. The DACL grants a SID without
// caring which it is, and an administrator restricting the daemon to a single
// service account should not have to create a group for it.
func resolveAllowGroup(value string) (string, error) {
	if kind, rest, ok := cutKind(value); ok {
		if kind != allowGroupKindSID {
			return "", fmt.Errorf("unsupported principal kind %q, use an account name or %s:<SID>", kind, allowGroupKindSID)
		}
		return sidPrincipal(rest)
	}

	if _, err := windows.StringToSid(value); err == nil {
		return sidPrincipal(value)
	}

	sid, _, _, err := windows.LookupSID("", value)
	if err != nil {
		return "", fmt.Errorf("look up account: %w", err)
	}
	return allowGroupKindSID + ":" + sid.String(), nil
}

// checkAllowGroupSet accepts any number of principals: a pipe descriptor holds
// one ACE per principal.
func checkAllowGroupSet([]string) error { return nil }

// applySocketAccess applies the restriction to a Unix socket, which on Windows
// it cannot: AF_UNIX sockets there carry no mode, and the daemon has no way to
// keep another local process off one. Serving it unrestricted would be the
// fail-open this flag exists to prevent, so a configured restriction is an
// error instead.
//
// The pipe transport is unaffected: its access lives in the security descriptor
// it is created with, and restrict never routes a named pipe here.
func applySocketAccess(path string, principals []string) error {
	if len(principals) == 0 {
		return nil
	}
	return fmt.Errorf("cannot restrict the unix socket %s on windows: it carries no access mode, serve the daemon on npipe:// instead", path)
}

// listenUnixPrivate binds a Unix socket. Windows has no umask and no mode on
// these sockets, so binding is all there is to do; a configured restriction is
// refused by applySocketAccess before the daemon serves.
func listenUnixPrivate(address string) (net.Listener, error) {
	return net.Listen("unix", address)
}

// allowedPipeSDDL renders the security descriptor for the daemon control pipe.
// An empty principal list yields the descriptor that lets any local caller
// connect.
func allowedPipeSDDL(principals []string) (string, error) {
	sids := make([]string, 0, len(principals))
	for _, principal := range principals {
		sid, ok := principalValue(principal, allowGroupKindSID)
		if !ok {
			return "", fmt.Errorf("not a %s principal: %q", allowGroupKindSID, principal)
		}
		sids = append(sids, sid)
	}
	return ipcauth.RestrictedPipeSDDL(sids), nil
}

func sidPrincipal(value string) (string, error) {
	sid, err := windows.StringToSid(value)
	if err != nil {
		return "", fmt.Errorf("parse SID %q: %w", value, err)
	}
	return allowGroupKindSID + ":" + sid.String(), nil
}
