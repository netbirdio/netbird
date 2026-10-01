//go:build !linux || android

package conntrack

import nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"

func New(flowLogger nftypes.FlowLogger, iface nftypes.IFaceMapper) nftypes.ConnTracker {
	return nil
}
