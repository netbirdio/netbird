package cmd

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata")

func usageFixture() *proto.GetAgentNetworkInfoResponse {
	computedAt := time.Date(2026, 11, 6, 14, 18, 0, 0, time.UTC)
	hour := computedAt.Truncate(time.Hour)
	month := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	return &proto.GetAgentNetworkInfoResponse{
		State:      proto.GetAgentNetworkInfoResponse_OK,
		UserEmail:  "ada@example.com",
		Endpoint:   "https://violet.eu.proxy.netbird.io",
		ComputedAt: timestamppb.New(computedAt),
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
						Source: proto.AgentNetworkLimit_ACCOUNT_RULE, SourceId: "rule-1", SourceName: "Monthly spend",
						Unit: proto.AgentNetworkLimit_USD, Scope: proto.AgentNetworkLimit_USER,
						Cap: 50, Used: 12.345, WindowSeconds: 2_592_000,
						WindowStart: timestamppb.New(month), ResetsAt: timestamppb.New(month.Add(30 * 24 * time.Hour)),
					},
					{
						Source: proto.AgentNetworkLimit_POLICY, SourceId: "pol-1", SourceName: "Engineers",
						Unit: proto.AgentNetworkLimit_TOKENS, Scope: proto.AgentNetworkLimit_GROUP,
						GroupId: "grp-eng", GroupName: "Engineering",
						Cap: 1_000_000, Used: 250_500, WindowSeconds: 3600,
						WindowStart: timestamppb.New(hour), ResetsAt: timestamppb.New(hour.Add(time.Hour)),
					},
				},
			},
			{
				Id: "prov-bedrock", Name: "Bedrock prod", CatalogId: "bedrock",
				Exhausted: true, ExhaustedReason: "user token cap exhausted on policy pol-2 (used 1200 of 1000)",
				Limits: []*proto.AgentNetworkLimit{{
					Source: proto.AgentNetworkLimit_POLICY, SourceId: "pol-2", SourceName: "Interns",
					Unit: proto.AgentNetworkLimit_TOKENS, Scope: proto.AgentNetworkLimit_USER,
					Cap: 1000, Used: 1200, WindowSeconds: 3600,
					WindowStart: timestamppb.New(hour), ResetsAt: timestamppb.New(hour.Add(time.Hour)),
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

	expired := usageFixture()
	expired.LoginExpired = true

	cases := []struct {
		name   string
		resp   *proto.GetAgentNetworkInfoResponse
		asJSON bool
	}{
		{name: "ok", resp: usageFixture()},
		{name: "ok_json", resp: usageFixture(), asJSON: true},
		{name: "login_expired", resp: expired},
		{name: "no_providers", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_OK, UserEmail: "ada@example.com"}},
		{name: "no_user", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_NO_USER}},
		{name: "not_enabled", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_NOT_ENABLED}},
		{name: "not_enabled_json", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_NOT_ENABLED}, asJSON: true},
		{name: "user_blocked", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_USER_BLOCKED, LoginExpired: true}},
		{name: "management_unsupported", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED}},
		{name: "management_unsupported_json", resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED}, asJSON: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			// An error is what the user sees on stderr, with exit code 1.
			if err := renderAgentNetworkUsage(&out, tc.resp, tc.asJSON); err != nil {
				out.WriteString("error: " + err.Error() + "\n")
			}
			assertGolden(t, tc.name, out.Bytes())
		})
	}

	t.Run("not_connected", func(t *testing.T) {
		err := agentNetworkInfoError(gstatus.Error(codes.FailedPrecondition, "client is not running, run 'netbird up' first"))
		assertGolden(t, "not_connected", []byte("error: "+err.Error()+"\n"))
	})
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
