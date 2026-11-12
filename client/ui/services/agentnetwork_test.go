//go:build !android && !ios && !freebsd && !js

package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

func TestAgentNetworkInfoFromProto(t *testing.T) {
	resetsAt := time.Date(2026, 11, 6, 15, 0, 0, 0, time.UTC)
	got := agentNetworkInfoFromProto(&proto.GetAgentNetworkInfoResponse{
		State: proto.GetAgentNetworkInfoResponse_OK,
		Providers: []*proto.AgentNetworkProvider{{
			Id: "prov-1", Name: "OpenAI", CatalogId: "openai_api", Exhausted: true,
			Limits: []*proto.AgentNetworkLimit{{
				Source: proto.AgentNetworkLimit_ACCOUNT_RULE, Unit: proto.AgentNetworkLimit_USD,
				Scope: proto.AgentNetworkLimit_GROUP, GroupName: "Engineering", Cap: 5, Used: 5,
				ResetsAt: timestamppb.New(resetsAt),
			}, {Source: proto.AgentNetworkLimit_POLICY}},
		}},
	})

	assert.Equal(t, "ok", got.State, "the frontend matches on lower-case states")
	require.Len(t, got.Providers, 1)
	assert.NotNil(t, got.Providers[0].Models, "empty lists must serialize as [] for the frontend")
	require.Len(t, got.Providers[0].Limits, 2)
	l := got.Providers[0].Limits[0]
	assert.Equal(t, "account_rule", l.Source)
	assert.Equal(t, "usd", l.Unit)
	assert.Equal(t, "group", l.Scope)
	assert.Equal(t, "2026-11-06T15:00:00Z", l.ResetsAt)
	assert.Empty(t, got.Providers[0].Limits[1].ResetsAt, "an unset timestamp stays empty")

	for state, want := range map[proto.GetAgentNetworkInfoResponse_State]string{
		proto.GetAgentNetworkInfoResponse_NO_USER:                "no_user",
		proto.GetAgentNetworkInfoResponse_NOT_ENABLED:            "not_enabled",
		proto.GetAgentNetworkInfoResponse_USER_BLOCKED:           "user_blocked",
		proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED: "management_unsupported",
	} {
		assert.Equal(t, want, agentNetworkInfoFromProto(&proto.GetAgentNetworkInfoResponse{State: state}).State)
	}
}
