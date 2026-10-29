//go:build windows

package ipcauth

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// PipeServerTrusted reports an error unless the pipe behind conn was created by a
// principal this client may hand secrets to. Clients call it for a pipe whose name
// carries no guarantee of its own, which is any name outside the
// ProtectedPrefix\Administrators namespace: that namespace already restricts
// creation to administrators and LocalSystem, while a plain name can be created by
// any local user before the daemon gets there.
//
// The decision is made from the pipe object's owner, not from the serving process,
// because a client cannot open a process running as another user at all, and the
// legitimate case is precisely an unprivileged client talking to a privileged
// daemon. Trusted owners are the service accounts, BUILTIN\Administrators, and
// this client's own user, the last of which is the daemon a user runs themselves
// as in netstack mode. A pipe owned by anyone else gets no setup key, pre-shared
// key or SSO prompt out of this client.
func PipeServerTrusted(conn net.Conn) error {
	// go-winio's pipe connection embeds *win32File, which exposes Fd().
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("connection %T does not expose a pipe handle", conn)
	}

	owner, err := pipeOwnerSID(windows.Handle(fdConn.Fd()))
	if err != nil {
		return err
	}

	if !trustedPipeOwner(owner) {
		return fmt.Errorf("pipe owned by %s, which is neither an administrator nor this user", owner)
	}
	return nil
}

// PipeOwnedBySelf reports whether the pipe behind conn was created by this very
// user, which is how a client recognises a daemon running as itself. Ownership it
// cannot read is reported as false.
func PipeOwnedBySelf(conn net.Conn) bool {
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return false
	}

	owner, err := pipeOwnerSID(windows.Handle(fdConn.Fd()))
	if err != nil {
		log.Debugf("read daemon pipe owner: %v", err)
		return false
	}
	return selfKnown && selfIdentity.SID != "" && owner == selfIdentity.SID
}

// pipeOwnerSID reads the owner of the pipe object a client is connected to. The
// handle was opened with GENERIC_READ, which includes READ_CONTROL, so no extra
// access is needed.
func pipeOwnerSID(handle windows.Handle) (string, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("read pipe security info: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return "", fmt.Errorf("read pipe owner: %w", err)
	}
	return owner.String(), nil
}

// trustedPipeOwner reports whether a pipe's owner is a principal a client may
// speak to. An elevated process's objects are owned by BUILTIN\Administrators by
// default, an unelevated one's by the user, which is why both forms appear here.
func trustedPipeOwner(owner string) bool {
	switch owner {
	case sidLocalSystem, sidLocalService, sidNetworkService, sidAdministrators:
		return true
	}
	return selfKnown && selfIdentity.SID != "" && owner == selfIdentity.SID
}
