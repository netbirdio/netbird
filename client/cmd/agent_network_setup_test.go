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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/agentnetwork/harness"
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
	t.Setenv("CODEX_HOME", filepath.Join(root, "codex"))
	t.Setenv("PI_CODING_AGENT_DIR", filepath.Join(root, "pi"))

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

func TestAgentNetworkSetupOpenAIHarnesses(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(endpoint.Close)
	addr, _ := anSetupTestHost(t, &proto.GetAgentNetworkInfoResponse{
		State:    proto.GetAgentNetworkInfoResponse_OK,
		Endpoint: endpoint.URL,
		Providers: []*proto.AgentNetworkProvider{
			{Id: "p1", Name: "OpenAI", CatalogId: "openai_api", ApiFlavor: "openai", Models: []string{"gpt-5.5"}},
		},
	})
	root := filepath.Dir(os.Getenv("CODEX_HOME"))
	codexFile := filepath.Join(root, "codex", "config.toml")
	openCodeFile := filepath.Join(root, "opencode", "opencode.jsonc")
	piModels := filepath.Join(root, "pi", "models.json")
	piSettings := filepath.Join(root, "pi", "settings.json")

	out, err := runAgentNetworkCmd(addr, "setup", "codex", "--dry-run")
	require.NoError(t, err, out)
	assert.Contains(t, out, `model_providers.netbird.base_url: (absent) -> "`+endpoint.URL+`/v1"`, "dry run shows the TOML keys")
	assert.Contains(t, out, "CODEX_CA_CERTIFICATE", "the warning names Codex's CA variable")
	_, err = os.Stat(codexFile)
	assert.True(t, os.IsNotExist(err), "dry run writes nothing")

	for _, h := range []string{"codex", "opencode", "pi"} {
		out, err = runAgentNetworkCmd(addr, "setup", h)
		require.NoError(t, err, out)
		assert.Contains(t, out, "set up for Agent Networks", h)
	}
	data, err := os.ReadFile(codexFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "model_provider = \"netbird\"\n", "Codex defaults to the netbird provider")
	data, err = os.ReadFile(openCodeFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"model": "netbird/gpt-5.5"`)
	data, err = os.ReadFile(piSettings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"defaultProvider":"netbird","defaultModel":"gpt-5.5"}`, string(data))

	out, err = runAgentNetworkCmd(addr, "setup", "list")
	require.NoError(t, err, out)
	assert.Contains(t, out, "claude-code    Claude Code    not configured")
	assert.Contains(t, out, "codex          Codex          configured")
	assert.Contains(t, out, "opencode       OpenCode       configured")
	assert.Contains(t, out, "pi             Pi             configured ("+piModels+", "+piSettings+")", "list shows both pi files")

	out, err = runAgentNetworkCmd(addr, "setup", "undo", "pi")
	require.NoError(t, err, out)
	data, err = os.ReadFile(piModels)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(data), "undo empties models.json")

	// A file the codec cannot round-trip is printed instead of written.
	require.NoError(t, os.WriteFile(openCodeFile, []byte("{\n  // mine\n}\n"), 0o600))
	out, err = runAgentNetworkCmd(addr, "setup", "opencode", "--force")
	require.Error(t, err)
	assert.Contains(t, out, "Add these settings by hand", "JSONC falls back to printing")
	assert.Contains(t, out, `"npm": "@ai-sdk/openai-compatible"`)
}

func TestAgentNetworkSetupRefusals(t *testing.T) {
	cases := []struct {
		name string
		resp *proto.GetAgentNetworkInfoResponse
		args []string
		want []string
	}{
		{
			name: "unknown state fails closed",
			resp: &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_STATE_UNSPECIFIED, Endpoint: "https://x"},
			want: []string{"unknown Agent Networks state"},
		},
		{
			name: "openai only",
			resp: &proto.GetAgentNetworkInfoResponse{
				State: proto.GetAgentNetworkInfoResponse_OK, Endpoint: "https://127.0.0.1:1",
				Providers: []*proto.AgentNetworkProvider{{Name: "OpenAI", CatalogId: "openai_api", ApiFlavor: "openai", AllModelsAllowed: true}},
			},
			want: []string{"Claude Code cannot use any provider available to you: OpenAI (openai)"},
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
				Providers: []*proto.AgentNetworkProvider{{Name: "V", CatalogId: "vertex_ai_api", AllModelsAllowed: true}},
			},
			want: []string{"needs --vertex-project"},
		},
		{
			// An allowlist that matches none of the provider's models: the
			// proxy denies every request, so setup must not write a config.
			name: "named provider allows no model",
			resp: &proto.GetAgentNetworkInfoResponse{
				State: proto.GetAgentNetworkInfoResponse_OK, Endpoint: "https://127.0.0.1:1",
				Providers: []*proto.AgentNetworkProvider{{Name: "A", CatalogId: "anthropic_api", ApiFlavor: "anthropic"}},
			},
			args: []string{"--provider", "A", "--model", "claude-opus-5"},
			want: []string{"no model on A is allowed for this peer"},
		},
		{
			name: "only provider allows no model",
			resp: &proto.GetAgentNetworkInfoResponse{
				State: proto.GetAgentNetworkInfoResponse_OK, Endpoint: "https://127.0.0.1:1",
				Providers: []*proto.AgentNetworkProvider{{Name: "A", CatalogId: "anthropic_api", ApiFlavor: "anthropic"}},
			},
			want: []string{"no model on A is allowed for this peer"},
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

func TestAgentNetworkSetupSkipsProviderWithNoModel(t *testing.T) {
	addr, _ := anSetupTestHost(t, &proto.GetAgentNetworkInfoResponse{
		State:    proto.GetAgentNetworkInfoResponse_OK,
		Endpoint: "https://127.0.0.1:1",
		Providers: []*proto.AgentNetworkProvider{
			{Name: "Blocked", CatalogId: "anthropic_api", ApiFlavor: "anthropic"},
			{Name: "Open", CatalogId: "anthropic_api", ApiFlavor: "anthropic", AllModelsAllowed: true},
		},
	})
	out, err := runAgentNetworkCmd(addr, "setup", "claude-code", "--dry-run")
	require.NoError(t, err, out)
	assert.Contains(t, out, "Provider: Open", "the provider with no allowed model is skipped")
}

func TestAgentNetworkSetupHidesKeyHelper(t *testing.T) {
	addr, settings := anSetupTestHost(t, &proto.GetAgentNetworkInfoResponse{
		State:     proto.GetAgentNetworkInfoResponse_OK,
		Endpoint:  "https://127.0.0.1:1",
		Providers: []*proto.AgentNetworkProvider{{Name: "A", CatalogId: "anthropic_api", ApiFlavor: "anthropic", AllModelsAllowed: true}},
	})
	require.NoError(t, os.MkdirAll(filepath.Dir(settings), 0o700))
	require.NoError(t, os.WriteFile(settings, []byte(`{"apiKeyHelper":"echo sk-ant-secret"}`), 0o600))

	out, err := runAgentNetworkCmd(addr, "setup", "claude-code", "--dry-run")
	require.Error(t, err, "the user's helper is a conflict")
	assert.NotContains(t, out, "sk-ant-secret", "the user's key helper is not printed")
	assert.Contains(t, out, "apiKeyHelper: (set, hidden) -> \"echo '-'\"", "NetBird's own helper is shown")

	out, err = runAgentNetworkCmd(addr, "setup", "claude-code", "--force")
	require.NoError(t, err, out)
	out, err = runAgentNetworkCmd(addr, "setup", "undo", "claude-code", "--dry-run")
	require.NoError(t, err, out)
	assert.NotContains(t, out, "sk-ant-secret", "the value undo restores is not printed")
}

func TestAnSetupCheckEndpointIgnoresProxy(t *testing.T) {
	// A proxy that records whether anything reached it.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	reached := make(chan struct{}, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
		reached <- struct{}{}
	}()
	t.Setenv("HTTPS_PROXY", "http://"+lis.Addr().String())
	t.Setenv("NO_PROXY", "")

	// TEST-NET-1 never answers; loopback would bypass the proxy anyway.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	def, err := harness.Lookup("claude-code")
	require.NoError(t, err)
	err = anSetupCheckEndpoint(ctx, def, "https://192.0.2.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS_PROXY", "the warning mentions the proxy the agent may use")
	select {
	case <-reached:
		t.Fatal("the probe went through the proxy instead of the overlay")
	default:
	}
}
