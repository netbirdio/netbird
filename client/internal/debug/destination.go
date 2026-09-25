package debug

import (
	"github.com/netbirdio/netbird/upload-server/types"
)

// ResolveUploadURL decides where a debug bundle is uploaded, taking the first
// destination that is set:
//
//   - mdm is the debugBundleUploadURL policy on this device. It outranks
//     everything, including a URL the caller named: pinning the destination on a
//     managed device is pointless if the person at the keyboard can send the
//     bundle elsewhere.
//   - requested is what this particular bundle asked for — the CLI's
//     --upload-bundle-url, or a remote job's upload_url. The callers that accept
//     one gate it separately (see requirePrivilegeForUploadURL: any host other
//     than the default needs a privileged caller).
//   - published is what the management server of this deployment advertises,
//     which the engine holds (Engine.DebugUploadURL).
//
// With none of them, the upload service NetBird runs is the default, for a
// self-hosted deployment as much as for a cloud one: an operator who needs the
// bundles to stay inside their own infrastructure points one of the knobs at
// their own upload service, and until they do the everyday "collect a bundle and
// send it to support" flow keeps working.
//
// Every caller goes through here rather than ordering the sources itself, so a
// path cannot quietly skip one of them.
func ResolveUploadURL(mdm, requested, published string) string {
	if mdm != "" {
		return mdm
	}

	if requested != "" {
		return requested
	}

	if published != "" {
		return published
	}

	return types.DefaultBundleURL
}
