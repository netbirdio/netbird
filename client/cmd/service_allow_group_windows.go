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

// applySocketAccess is a no-op on Windows, where access is decided by the
// security descriptor the pipe is created with rather than by a mode set on it
// afterwards. See allowedPipeSDDL.
func applySocketAccess(string, []string) error { return nil }

// listenUnixPrivate binds a Unix socket. Windows has no umask, and a Unix
// socket there carries no mode the daemon could narrow, so there is nothing to
// do beyond binding it. A restriction on this transport is refused before it
// gets here: see listenOnAddress.
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
