//go:build !android && !ios

package server

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/configs"
	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/upload-server/types"
)

// uiLogFileName is the only file name the daemon accepts as a UI log path. The
// UI (writer), this validation, and the bundle collector all read it from
// configs so they cannot drift.
const uiLogFileName = configs.UILogFile

// uiLogOpener opens the registered UI log, and its rotated siblings, on behalf
// of the caller requesting the bundle: OpenOwnedFile then collects the log only
// when that caller owns it (or is privileged). identified is false on a socket
// that carries no caller identity, in which case nothing is opened.
func uiLogOpener(id ipcauth.Identity, identified bool) debug.LogOpener {
	return func(path string) (*os.File, error) {
		if !identified {
			return nil, fmt.Errorf("bundle requester has no verified identity")
		}
		return ipcauth.OpenOwnedFile(id, path)
	}
}

// requirePrivilegeForUploadURL restricts where the daemon may send a debug
// bundle. The bundle holds the daemon's own logs and state, and the daemon
// fetches the upload URL itself, so an unrestricted endpoint turns the daemon
// into both an exfiltration channel and a request forwarder that reaches
// services only it can talk to.
//
// The upload service NetBird publishes is open to any caller, since that is what
// the CLI and the desktop UI use. Any other endpoint, self-hosted upload servers
// included, requires a privileged caller. Plaintext is refused for everyone: the
// daemon fetches the URL and then PUTs the bundle to whatever that fetch returns,
// so an http hop is a place to intercept the bundle or the redirect.
//
// insecure relaxes transport security (http, or an untrusted TLS certificate)
// for a self-hosted server. It weakens a root-privileged upload, so it is
// refused for an unprivileged caller regardless of the host.
func requirePrivilegeForUploadURL(ctx context.Context, rawURL string, insecure bool) error {
	if rawURL == "" {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return gstatus.Errorf(codes.InvalidArgument, "parse upload URL: %v", err)
	}

	// --insecure relaxes https to http or an untrusted certificate; it does not
	// widen the URL to arbitrary schemes, so a host and http/https are required
	// before the insecure branch takes over.
	if parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return gstatus.Errorf(codes.InvalidArgument, "upload URL must be http or https with a host")
	}

	if insecure {
		return denyPrivileged(ctx,
			"uploading a debug bundle without transport security (--upload-bundle-insecure)",
			ipcauth.ElevatedCommand("netbird debug bundle -U --upload-bundle-insecure --upload-bundle-url <url>"))
	}

	if parsed.Scheme != "https" {
		return gstatus.Errorf(codes.InvalidArgument, "upload URL must use https, got scheme %q", parsed.Scheme)
	}

	if isDefaultUploadService(parsed) {
		return nil
	}

	return denyPrivileged(ctx,
		"uploading a debug bundle to an upload service other than the default one",
		ipcauth.ElevatedCommand("netbird debug bundle -U --upload-bundle-url <url>"))
}

// isDefaultUploadService reports whether the URL points at the upload service
// NetBird runs. Only the host is compared: the service's path may differ between
// releases, and the host is what decides who receives the bundle.
func isDefaultUploadService(parsed *url.URL) bool {
	defaultURL, err := url.Parse(types.DefaultBundleURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == defaultURL.Scheme && strings.EqualFold(parsed.Host, defaultURL.Host)
}
