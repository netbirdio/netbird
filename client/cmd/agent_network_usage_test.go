package cmd

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata")

// usageNow is the local clock the reset countdowns are rendered against.
var usageNow = time.Date(2026, 11, 6, 14, 18, 0, 0, time.UTC)

func usageFixture() *proto.GetAgentNetworkInfoResponse {
	hour := usageNow.Truncate(time.Hour)
	month := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	return &proto.GetAgentNetworkInfoResponse{
		State:    proto.GetAgentNetworkInfoResponse_OK,
		Endpoint: "https://violet.eu.proxy.netbird.io",
		Providers: []*proto.AgentNetworkProvider{
			{
				Id: "prov-anthropic", Name: "Anthropic", CatalogId: "anthropic_api", ApiFlavor: "anthropic",
				AllModelsAllowed: true, Unlimited: true,
			},
			{
				Id: "prov-openai", Name: "OpenAI", CatalogId: "openai_api", ApiFlavor: "openai",
				Models: []string{"gpt-5.4"},
				Limits: []*proto.AgentNetworkLimit{
					{
						Unit: proto.AgentNetworkLimit_USD,
						Cap:  50, Used: 12.345, ResetsAt: timestamppb.New(month.Add(30 * 24 * time.Hour)),
					},
					{
						Unit: proto.AgentNetworkLimit_TOKENS,
						Cap:  1_000_000, Used: 250_500, ResetsAt: timestamppb.New(hour.Add(time.Hour)),
					},
				},
			},
			{
				Id: "prov-bedrock", Name: "Bedrock prod", CatalogId: "bedrock",
				Exhausted: true,
				Limits: []*proto.AgentNetworkLimit{{
					Unit: proto.AgentNetworkLimit_TOKENS,
					Cap:  1000, Used: 1200, ResetsAt: timestamppb.New(hour.Add(time.Hour)),
				}},
			},
		},
	}
}

func TestRenderAgentNetworkUsage_Golden(t *testing.T) {
	// Absolute reset times print in local time; pin it so the goldens hold
	// on every machine.
	local := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = local })

	cases := []struct {
		name   string
		resp   *proto.GetAgentNetworkInfoResponse
		asJSON bool
	}{
		{name: "ok", resp: usageFixture()},
		{name: "ok_json", resp: usageFixture(), asJSON: true},
		{name: "reset_passed", resp: resetPassedFixture()},
		{name: "no_providers", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_OK}},
		{name: "not_enabled", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_NOT_ENABLED}},
		{name: "not_enabled_json", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_NOT_ENABLED}, asJSON: true},
		{name: "user_blocked", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_USER_BLOCKED}},
		{name: "management_unsupported", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED}},
		{name: "management_unsupported_json", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED}, asJSON: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := renderAgentNetworkUsage(&out, tc.resp, usageNow, tc.asJSON); err != nil {
				out.WriteString(commandErrorText(err))
			}
			assertGolden(t, tc.name, out.Bytes())
		})
	}

	t.Run("not_connected", func(t *testing.T) {
		err := agentNetworkInfoError(gstatus.Error(codes.FailedPrecondition, "client is not running, run 'netbird up' first"))
		assertGolden(t, "not_connected", []byte(commandErrorText(err)))
	})
}

// commandErrorText is what the user sees on stderr, with exit code 1, when
// the command returns err.
func commandErrorText(err error) string {
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&buf)
	printCommandError(cmd, err)
	return buf.String()
}

// resetPassedFixture has a reset that management placed before the client
// clock, as happens when the two clocks disagree.
func resetPassedFixture() *proto.GetAgentNetworkInfoResponse {
	return &proto.GetAgentNetworkInfoResponse{
		State: proto.GetAgentNetworkInfoResponse_OK,
		Providers: []*proto.AgentNetworkProvider{{
			Id: "prov-openai", Name: "OpenAI", CatalogId: "openai_api",
			Exhausted: true,
			Limits: []*proto.AgentNetworkLimit{{
				Unit: proto.AgentNetworkLimit_TOKENS,
				Cap:  1000, Used: 1000, ResetsAt: timestamppb.New(usageNow.Add(-2 * time.Minute)),
			}},
		}},
	}
}

func TestAgentNetworkInfoError_OtherErrorsKeepContext(t *testing.T) {
	err := agentNetworkInfoError(gstatus.Error(codes.Unavailable, "management unreachable"))
	assert.Contains(t, err.Error(), "management unreachable", "the daemon's reason must reach the user")
}

func TestGroupThousands(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -1000: "-1,000"} {
		assert.Equal(t, want, groupThousands(in), "groupThousands(%d)", in)
	}
}

func TestFormatLimitAmount_UnknownUnit(t *testing.T) {
	got := formatLimitAmount(proto.AgentNetworkLimit_Unit(99), 12.5, true)
	assert.Equal(t, "12.5 (unknown unit)", got, "an unknown unit must not be shown as tokens")
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "agent_network_usage", name+".golden")
	if *updateGolden {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o600))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "golden file missing; run go test -run Golden ./client/cmd/ -update")
	// Windows checkouts may convert the goldens to CRLF.
	assert.Equal(t, strings.ReplaceAll(string(want), "\r\n", "\n"), string(got), "output must match %s", path)
}
