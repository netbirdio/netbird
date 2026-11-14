package grpc

import (
	"fmt"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// alignedHeartbeat is the aligned heartbeat of one Sync stream: the schedule
// Management sends on and the signed phase the client hands to Signal and relay.
type alignedHeartbeat struct {
	answer alignedhb.Answer
	signed alignedhb.SignedPhase
}

// resign returns the aligned heartbeat of the day of now when it differs from
// the day a was signed for, nil when the day is the same or it cannot be signed.
func (a *alignedHeartbeat) resign(signer *phasesig.Signer, peerKey wgtypes.Key, now time.Time) *alignedHeartbeat {
	if a == nil || signer == nil || phasesig.Day(now) == a.signed.Day {
		return nil
	}
	period := a.answer.Period
	signed, err := signer.SignedPhase(messages.HashID(peerKey.String()), period, now)
	if err != nil {
		log.Debugf("no aligned heartbeat phase of the new day for peer %s: %v", peerKey.String(), err)
		return nil
	}
	return &alignedHeartbeat{answer: alignedhb.Answer{Period: period, Phase: signed.Phase}, signed: signed}
}

// config returns the peer config form of a.
func (a *alignedHeartbeat) config() *proto.AlignedHeartbeatConfig {
	return &proto.AlignedHeartbeatConfig{
		Enabled:        true,
		PeriodSeconds:  alignedhb.PeriodSeconds(a.answer.Period),
		PhaseMillis:    uint32(a.answer.Phase.Milliseconds()),
		PhaseSignature: a.signed.Signature,
		PhaseDay:       a.signed.Day,
	}
}

// newPhaseSigner returns the phase signer built from the relay auth secret, nil
// when no secret is configured. Without a signer Management answers no aligned
// heartbeat request, so every stream stays stock.
func newPhaseSigner(relay *nbconfig.Relay) *phasesig.Signer {
	if relay == nil || relay.Secret == "" {
		log.Infof("aligned heartbeat disabled: no relay secret configured")
		return nil
	}
	signer, err := phasesig.NewSigner(relay.Secret)
	if err != nil {
		log.Warnf("aligned heartbeat disabled: %v", err)
		return nil
	}
	return signer
}

// newPeriodLimits returns the aligned heartbeat period limits from cfg. An
// unset limit takes its default. Limits outside the default range are an error.
func newPeriodLimits(cfg nbconfig.AlignedHeartbeat) (alignedhb.PeriodLimits, error) {
	limits := alignedhb.PeriodLimits{Min: cfg.MinPeriod.Duration, Max: cfg.MaxPeriod.Duration}
	if limits.Min == 0 {
		limits.Min = alignedhb.MinPeriod
	}
	if limits.Max == 0 {
		limits.Max = alignedhb.MaxPeriod
	}
	if err := limits.Validate(); err != nil {
		return alignedhb.PeriodLimits{}, fmt.Errorf("aligned heartbeat period limits: %w", err)
	}
	return limits, nil
}

// alignedHeartbeatAnswer returns the aligned heartbeat for a Sync stream, or nil
// when the client did not ask for it or there is no signer. A client asks with
// the capability in its meta and the period in the request, both on this stream.
// The period is clamped to limits and the phase signed for the clamped period,
// which the peer config confirms. The phase comes from the peer key and the day
// of now, so it is the same on every Management instance and after a restart.
func alignedHeartbeatAnswer(req *proto.SyncRequest, peerKey wgtypes.Key, signer *phasesig.Signer, limits alignedhb.PeriodLimits, now time.Time) *alignedHeartbeat {
	if signer == nil {
		return nil
	}
	if !slices.Contains(req.GetMeta().GetCapabilities(), proto.PeerCapability_PeerCapabilityAlignedHeartbeat) {
		return nil
	}
	seconds := req.GetAlignedHeartbeat().GetPeriodSeconds()
	if seconds == 0 {
		return nil
	}
	requested := time.Duration(seconds) * time.Second
	period := limits.Clamp(requested)
	if period != requested {
		log.Debugf("aligned heartbeat period %s of peer %s clamped to %s", requested, peerKey.String(), period)
	}
	signed, err := signer.SignedPhase(messages.HashID(peerKey.String()), period, now)
	if err != nil {
		log.Debugf("no aligned heartbeat for peer %s: %v", peerKey.String(), err)
		return nil
	}
	return &alignedHeartbeat{
		answer: alignedhb.Answer{Period: period, Phase: signed.Phase},
		signed: signed,
	}
}

// setAlignedHeartbeatConfig puts the aligned heartbeat into the peer config of
// the first response on the stream. A nil value leaves the response as it is, so
// a client that did not ask sees no change.
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
