package server

import (
	"context"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// bindCallerUsername enforces that a non-privileged caller may only operate on
// its OWN user's profiles. Profiles live in per-username directories, but the
// username is a client-supplied gRPC field the server historically never
// checked; binding it to the caller's kernel identity closes the "pass another
// user's username" hole. Privileged callers (root / elevated-admin) may manage
// any user's profiles.
func (s *Server) bindCallerUsername(ctx context.Context, requested string) error {
	if requested == "" {
		return nil // handlers validate emptiness themselves; nothing to bind
	}

	id, ok := ipcauth.IdentityFromContext(ctx)
	if !ok {
		return gstatus.Error(codes.PermissionDenied, "caller identity could not be verified")
	}
	if id.IsPrivileged() {
		return nil
	}

	caller, err := usernameForIdentity(id)
	if err != nil {
		log.Warnf("profile authz: resolve caller username for %s: %v", id, err)
		return gstatus.Error(codes.PermissionDenied, "could not resolve caller identity to a username")
	}
	if !usernamesEqual(requested, caller) {
		return gstatus.Errorf(codes.PermissionDenied,
			"not authorized to operate on another user's profiles (caller %q requested %q)", caller, requested)
	}
	return nil
}

// usernamesEqual compares usernames case-insensitively on Windows (domain
// accounts) and exactly on Unix.
func usernamesEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
