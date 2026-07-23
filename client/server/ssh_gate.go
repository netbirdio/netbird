package server

import (
	"context"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// requirePrivilegedForDangerousSSH enforces M-SSHGATE: enabling SSH root login
// or disabling SSH authentication turns the root/LocalSystem daemon's SSH server
// into an unauthenticated root shell (local-to-remote-root escalation), so only
// a privileged caller (Unix root, or Windows elevated-admin/LocalSystem) may set
// these flags to true over the local IPC.
//
// It gates the request fields, not the resulting config: a value already
// persisted (e.g. set previously by root, or by MDM/managed config) is untouched;
// only a new attempt to turn them on via SetConfig/Login is checked.
//
// When the caller identity cannot be verified (e.g. the daemon is on a TCP
// control channel with no peer credentials) it fails closed — refusing rather
// than letting an unauthenticated local caller flip these flags.
func requirePrivilegedForDangerousSSH(ctx context.Context, enableSSHRoot, disableSSHAuth *bool) error {
	dangerous := (enableSSHRoot != nil && *enableSSHRoot) || (disableSSHAuth != nil && *disableSSHAuth)
	if !dangerous {
		return nil
	}

	id, ok := ipcauth.IdentityFromContext(ctx)
	if !ok {
		log.Warnf("denying SSH root/no-auth config change: caller identity unavailable on this control channel")
		return gstatus.Error(codes.PermissionDenied,
			"enabling SSH root login or disabling SSH authentication requires root/administrator, but the caller identity could not be verified on this daemon control channel")
	}
	if !id.IsPrivileged() {
		log.Warnf("denying SSH root/no-auth config change from non-privileged caller %s", id)
		return gstatus.Errorf(codes.PermissionDenied,
			"enabling SSH root login or disabling SSH authentication requires root/administrator (caller %s is not privileged); rerun as root/administrator", id)
	}
	return nil
}
