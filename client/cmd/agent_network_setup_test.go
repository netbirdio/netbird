package cmd

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
)

type anSetupFakeDaemon struct {
	proto.UnimplementedDaemonServiceServer
	resp *proto.GetAgentNetworkInfoResponse
}

func (f *anSetupFakeDaemon) GetAgentNetworkInfo(context.Context, *proto.GetAgentNetworkInfoRequest) (*proto.GetAgentNetworkInfoResponse, error) {
	return f.resp, nil
}

// anSetupTestHost serves resp from a fake daemon and points every config
// location at temp dirs, returning the Claude Code settings path.
func anSetupTestHost(t *testing.T, resp *proto.GetAgentNetworkInfoResponse) (string, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterDaemonServiceServer(srv, &anSetupFakeDaemon{resp: resp})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	root := t.TempDir()
	for _, k := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA"} {
		t.Setenv(k, root)
	}
	claudeDir := filepath.Join(root, "claude")
	t.Setenv("CLAUDE_CONFIG_DIR", claudeDir)

	origAddr := daemonAddr
	t.Cleanup(func() { daemonAddr = origAddr })
	return "tcp://" + lis.Addr().String(), filepath.Join(claudeDir, "settings.json")
}

func runAgentNetworkCmd(addr string, args ...string) (string, error) {
	daemonAddr = addr
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append(append([]string{"agent-network"}, args...), "--daemon-addr", addr, "--log-file", ""))
	err := rootCmd.Execute()
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetArgs(nil)
	resetFlags(rootCmd)
	return out.String(), err
}

func TestAgentNetworkSetupClaudeCode(t *testing.T) {
	// A self-signed endpoint: the check must flag TLS but setup still writes.
	endpoint := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(endpoint.Close)

	addr, settings := anSetupTestHost(t, &proto.GetAgentNetworkInfoResponse{
		State:    proto.GetAgentNetworkInfoResponse_OK,
		Endpoint: endpoint.URL,
		Providers: []*proto.AgentNetworkProvider{
			{Id: "p1", Name: "OpenAI", CatalogId: "openai_api", ApiFlavor: "openai", Models: []string{"gpt-5.5"}},
			{Id: "p2", Name: "Anthropic", CatalogId: "anthropic_api", ApiFlavor: "anthropic", Models: []string{"claude-opus-5", "claude-haiku-4-5"}},
		},
	})

	out, err := runAgentNetworkCmd(addr, "setup", "claude-code", "--dry-run")
	require.NoError(t, err, out)
	assert.Contains(t, out, "Provider: Anthropic", "the OpenAI provider is skipped")
	assert.Contains(t, out, "env.ANTHROPIC_BASE_URL: (absent) -> \""+endpoint.URL+"\"", "dry run shows before and after")
	assert.Contains(t, out, "NODE_EXTRA_CA_CERTS", "an untrusted certificate is flagged")
	_, err = os.Stat(settings)
	assert.True(t, os.IsNotExist(err), "dry run writes nothing")

	out, err = runAgentNetworkCmd(addr, "setup", "claude-code", "--model", "claude-haiku-4-5")
	require.NoError(t, err, out)
	assert.Contains(t, out, "claude.ai login stays saved", "the user is told about the login and undo")
	data, err := os.ReadFile(settings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"apiKeyHelper":"echo '-'","model":"claude-haiku-4-5","env":{"ANTHROPIC_BASE_URL":"`+endpoint.URL+`"}}`, string(data))

	out, err = runAgentNetworkCmd(addr, "setup", "list")
	require.NoError(t, err, out)
	assert.Contains(t, out, "claude-code    Claude Code    configured")

	out, err = runAgentNetworkCmd(addr, "setup", "undo", "claude-code")
	require.NoError(t, err, out)
	data, err = os.ReadFile(settings)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(data), "undo removes every key setup wrote")
}

func TestAgentNetworkSetupRefusals(t *testing.T) {
	cases := []struct {
		name string
		resp *proto.GetAgentNetworkInfoResponse
		args []string
		want []string
	}{
		{
			name: "no user",
			resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_NO_USER},
			want: []string{"not available for this peer"},
		},
		{
			name: "unknown state fails closed",
			resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_STATE_UNSPECIFIED, Endpoint: "https://x"},
			want: []string{"unknown Agent Networks state"},
		},
		{
			name: "openai only",
			resp: &proto.GetAgentNetworkInfoResponse{
				State: proto.GetAgentNetworkInfoResponse_OK, Endpoint: "https://127.0.0.1:1", LoginExpired: true,
				Providers: []*proto.AgentNetworkProvider{{Name: "OpenAI", CatalogId: "openai_api", ApiFlavor: "openai"}},
			},
			want: []string{"Claude Code cannot use any provider available to you: OpenAI (openai)", "Your NetBird login expired"},
		},
		{
			name: "model not allowed",
			resp: &proto.GetAgentNetworkInfoResponse{
				State: proto.GetAgentNetworkInfoResponse_OK, Endpoint: "https://127.0.0.1:1",
				Providers: []*proto.AgentNetworkProvider{{Name: "A", CatalogId: "anthropic_api", ApiFlavor: "anthropic", Models: []string{"claude-opus-5"}}},
			},
			args: []string{"--model", "claude-mythos"},
			want: []string{`model "claude-mythos" is not allowed on A`},
		},
		{
			name: "vertex needs project",
			resp: &proto.GetAgentNetworkInfoResponse{
				State: proto.GetAgentNetworkInfoResponse_OK, Endpoint: "https://127.0.0.1:1",
				Providers: []*proto.AgentNetworkProvider{{Name: "V", CatalogId: "vertex_ai_api"}},
			},
			want: []string{"needs --vertex-project"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, settings := anSetupTestHost(t, tc.resp)
			out, err := runAgentNetworkCmd(addr, append([]string{"setup", "claude-code"}, tc.args...)...)
			require.Error(t, err)
			for _, w := range tc.want {
				assert.Contains(t, out+err.Error(), w)
			}
			_, err = os.Stat(settings)
			assert.True(t, os.IsNotExist(err), "a refused setup writes nothing")
		})
	}
}
