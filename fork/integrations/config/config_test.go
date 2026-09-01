// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func enabledFlowSettings() FlowSettings {
	return FlowSettings{
		Enabled:     true,
		Groups:      []string{"grp-flow"},
		ReceiverURL: "flows.example.com:443",
		TokenSecret: "s3cr3t",
		Interval:    42 * time.Second,
	}
}

func TestExtendConfig_PassThroughCases(t *testing.T) {
	flowEnabled := &types.ExtraSettings{FlowEnabled: true}

	tests := []struct {
		name          string
		settings      FlowSettings
		peerGroups    []string
		extraSettings *types.ExtraSettings
	}{
		{"pipeline disabled", FlowSettings{}, []string{"grp-flow"}, flowEnabled},
		{"nil extra settings", enabledFlowSettings(), []string{"grp-flow"}, nil},
		{"account flow flag off", enabledFlowSettings(), []string{"grp-flow"}, &types.ExtraSettings{}},
		{"peer in no flow group", enabledFlowSettings(), []string{"other"}, flowEnabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := extendConfig(tt.settings, "peer-1", tt.peerGroups, &proto.NetbirdConfig{}, tt.extraSettings)
			assert.Nil(t, cfg.Flow, "flow config must stay unset")
		})
	}
}

func TestExtendConfig_InjectsFlowForGroupMember(t *testing.T) {
	settings := enabledFlowSettings()
	extra := &types.ExtraSettings{
		FlowEnabled:              true,
		FlowPacketCounterEnabled: true,
		FlowENCollectionEnabled:  true,
		FlowDnsCollectionEnabled: false,
	}

	cfg := extendConfig(settings, "peer-1", []string{"other", "grp-flow"}, &proto.NetbirdConfig{}, extra)

	require.NotNil(t, cfg.Flow, "group member must receive the flow config")
	assert.True(t, cfg.Flow.Enabled)
	assert.Equal(t, settings.ReceiverURL, cfg.Flow.Url)
	assert.True(t, cfg.Flow.Counters, "counters mirror FlowPacketCounterEnabled")
	assert.True(t, cfg.Flow.ExitNodeCollection, "exit node collection mirrors FlowENCollectionEnabled")
	assert.False(t, cfg.Flow.DnsCollection, "dns collection mirrors FlowDnsCollectionEnabled")

	require.NotNil(t, cfg.Flow.Interval, "interval is mandatory, the agent errors on a missing one")
	assert.Equal(t, settings.Interval, cfg.Flow.Interval.AsDuration())

	require.NotEmpty(t, cfg.Flow.TokenPayload)
	mac := hmac.New(sha256.New, []byte(settings.TokenSecret))
	mac.Write([]byte(cfg.Flow.TokenPayload))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), cfg.Flow.TokenSignature,
		"token signature must verify against the configured secret")
}

func TestExtendConfig_SignsPerPeerToken(t *testing.T) {
	settings := enabledFlowSettings()
	extra := &types.ExtraSettings{FlowEnabled: true}

	first := extendConfig(settings, "peer-1", []string{"grp-flow"}, &proto.NetbirdConfig{}, extra)
	second := extendConfig(settings, "peer-2", []string{"grp-flow"}, &proto.NetbirdConfig{}, extra)

	require.NotNil(t, first.Flow)
	require.NotNil(t, second.Flow)
	assert.NotEqual(t, first.Flow.TokenPayload, second.Flow.TokenPayload,
		"each peer gets its own token so the receiver can attribute events")
}
