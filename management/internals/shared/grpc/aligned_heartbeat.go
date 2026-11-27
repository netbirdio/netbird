package grpc

import (
	"slices"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// alignedHeartbeat is the aligned heartbeat of one Sync stream: the clamped
// period the server confirmed and the phase it sends heartbeats on.
type alignedHeartbeat struct {
	period time.Duration
	phase  time.Duration
}

// alignedHeartbeatAnswer returns the aligned heartbeat for a Sync stream, or
// nil when the client did not ask for it. A client asks with the capability
// in its meta and the period in the request, both on this stream. The period
// is clamped to the fixed limits, and the phase is computed from the peer
// key, so it is the same on every Management instance and after a restart.
func alignedHeartbeatAnswer(req *proto.SyncRequest, peerKey wgtypes.Key) *alignedHeartbeat {
	if !slices.Contains(req.GetMeta().GetCapabilities(), proto.PeerCapability_PeerCapabilityAlignedHeartbeat) {
		return nil
	}
	seconds := req.GetAlignedHeartbeat().GetPeriodSeconds()
	if seconds == 0 {
		return nil
	}
	requested := time.Duration(seconds) * time.Second
	period := alignedhb.ClampPeriod(requested)
	if period != requested {
		log.Debugf("aligned heartbeat period %s of peer %s clamped to %s", requested, peerKey.String(), period)
	}
	return &alignedHeartbeat{
		period: period,
		phase:  alignedhb.Phase(messages.HashID(peerKey.String()), period),
	}
}

// config returns the peer config form of a.
func (a *alignedHeartbeat) config() *proto.AlignedHeartbeatConfig {
	return &proto.AlignedHeartbeatConfig{
		Enabled:       true,
		PeriodSeconds: alignedhb.PeriodSeconds(a.period),
	}
}

// setAlignedHeartbeatConfig puts the aligned heartbeat into the peer config
// of the first response on the stream. A nil value leaves the response as
// it is, so a client that did not ask sees no change.
func setAlignedHeartbeatConfig(resp *proto.SyncResponse, aligned *alignedHeartbeat) {
	if aligned == nil || resp == nil {
		return
	}
	cfg := aligned.config()
	if pc := resp.GetPeerConfig(); pc != nil {
		pc.AlignedHeartbeat = cfg
	}
	if pc := resp.GetNetworkMap().GetPeerConfig(); pc != nil {
		pc.AlignedHeartbeat = cfg
	}
}
