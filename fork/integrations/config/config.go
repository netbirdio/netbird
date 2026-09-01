// SPDX-License-Identifier: BSD-3-Clause

// Package config extends the sync-time NetbirdConfig with the flow logger
// configuration for peers in the configured flow groups.
package config

import (
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ExtendNetBirdConfig injects the flow logger configuration into the sync
// response for peers that are members of at least one configured flow group.
// Everything else is a pass-through, mirroring the original module.
func ExtendNetBirdConfig(peerID string, peerGroups []string, config *proto.NetbirdConfig, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
	return extendConfig(LoadFlowSettings(), peerID, peerGroups, config, extraSettings)
}

func extendConfig(settings FlowSettings, peerID string, peerGroups []string, config *proto.NetbirdConfig, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
	if !settings.Enabled || extraSettings == nil || !extraSettings.FlowEnabled {
		return config
	}
	if !settings.matchesAnyGroup(peerGroups) {
		return config
	}

	payload, signature := settings.signToken(peerID)
	config.Flow = &proto.FlowConfig{
		Url:                settings.ReceiverURL,
		TokenPayload:       payload,
		TokenSignature:     signature,
		Interval:           durationpb.New(settings.Interval),
		Enabled:            true,
		Counters:           extraSettings.FlowPacketCounterEnabled,
		ExitNodeCollection: extraSettings.FlowENCollectionEnabled,
		DnsCollection:      extraSettings.FlowDnsCollectionEnabled,
	}
	return config
}
