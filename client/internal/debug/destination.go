package debug

import (
	"errors"

	"github.com/netbirdio/netbird/client/internal/metrics"
	"github.com/netbirdio/netbird/upload-server/types"
)

// ErrNoUploadDestination reports that a bundle has nowhere to go: the
// management server of this deployment publishes no upload service, and the
// peer is not enrolled with NetBird's cloud either. A debug bundle carries the
// peer's logs, routes, DNS and firewall state, so the default is to keep it
// inside the operator's control sphere rather than fall back to the service
// NetBird runs.
var ErrNoUploadDestination = errors.New("this deployment publishes no debug bundle upload service; set it on the account settings or in the management server config, or pass an explicit upload URL")

// ResolveUploadURL decides where a debug bundle may be uploaded.
//
// requested is a destination a caller named explicitly (a CLI flag, the daemon
// request); it always wins, and the callers that accept one gate it separately.
// published is what the management server of this deployment advertises, which
// the engine holds (Engine.DebugUploadURL). With neither, only a peer enrolled
// with NetBird's cloud falls back to the service NetBird runs — for anyone else
// that would carry the bundle out of the deployment the operator controls, so it
// fails closed with ErrNoUploadDestination.
func ResolveUploadURL(requested, published, managementURL string) (string, error) {
	if requested != "" {
		return requested, nil
	}

	if published != "" {
		return published, nil
	}

	if metrics.DetermineDeploymentType(managementURL) == metrics.DeploymentTypeCloud {
		return types.DefaultBundleURL, nil
	}

	return "", ErrNoUploadDestination
}
