package debug

import (
	"github.com/netbirdio/netbird/upload-server/types"
)

// ResolveUploadURL decides where a debug bundle is uploaded.
//
// requested is a destination a caller named explicitly — an MDM override, the
// CLI's --upload-bundle-url, a remote job's upload_url; it always wins, and the
// callers that accept one gate it separately (see requirePrivilegeForUploadURL:
// any host other than the default needs a privileged caller). published is what
// the management server of this deployment advertises, which the engine holds
// (Engine.DebugUploadURL). With neither, the upload service NetBird runs is the
// default, for a self-hosted deployment as much as for a cloud one: an operator
// who needs the bundles to stay inside their own infrastructure points either
// knob at their own upload service, and until they do the everyday
// "collect a bundle and send it to support" flow keeps working.
func ResolveUploadURL(requested, published string) string {
	if requested != "" {
		return requested
	}

	if published != "" {
		return published
	}

	return types.DefaultBundleURL
}
