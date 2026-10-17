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
func resolveAllowGroup(value string) (ipcauth.Principal, error) {
	principal, typed, err := typedPrincipal(value, ipcauth.KindSID)
	if err != nil {
		return ipcauth.Principal{}, err
	}
	if typed {
		return sidPrincipal(principal.Value)
	}

	if _, err := windows.StringToSid(value); err == nil {
		return sidPrincipal(value)
	}

	sid, _, _, err := windows.LookupSID("", value)
	if err != nil {
		return ipcauth.Principal{}, fmt.Errorf("look up account: %w", err)
	}
	return sidPrincipal(sid.String())
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
func listenUnixPrivate(address string, _ []string) (net.Listener, error) {
	return net.Listen("unix", address)
}

// allowedPipeSDDL renders the security descriptor for the daemon control pipe.
// An empty principal list yields the descriptor that lets any local caller
// connect.
func allowedPipeSDDL(principals []string) (string, error) {
	sids := make([]string, 0, len(principals))
	for _, value := range principals {
		principal, err := principalOfKind(value, ipcauth.KindSID)
		if err != nil {
			return "", err
		}
		sids = append(sids, principal.Value)
	}
	return ipcauth.RestrictedPipeSDDL(sids), nil
}

// sidPrincipal validates a SID and renders it in its canonical form, so that
// two spellings of the same SID produce one principal.
func sidPrincipal(value string) (ipcauth.Principal, error) {
	sid, err := windows.StringToSid(value)
	if err != nil {
		return ipcauth.Principal{}, fmt.Errorf("parse SID %q: %w", value, err)
	}
	principal, ok := ipcauth.ParsePrincipal(ipcauth.SIDPrincipal(sid.String()))
	if !ok {
		return ipcauth.Principal{}, fmt.Errorf("build sid principal for %q", sid.String())
	}
	return principal, nil
}
