//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/agentnetwork/harness"
	"github.com/netbirdio/netbird/client/proto"
)

const testEndpoint = "https://agents.netbird.test"

// fakeDaemon answers GetAgentNetworkInfo; any other RPC panics on the nil
// embedded client.
type fakeDaemon struct {
	proto.DaemonServiceClient
	info *proto.GetAgentNetworkInfoResponse
}

func (f *fakeDaemon) GetAgentNetworkInfo(context.Context, *proto.GetAgentNetworkInfoRequest, ...grpc.CallOption) (*proto.GetAgentNetworkInfoResponse, error) {
	return f.info, nil
}

type fakeConn struct{ cli *fakeDaemon }

func (c fakeConn) Client() (proto.DaemonServiceClient, error) { return c.cli, nil }

type harnessHost struct {
	svc    *AgentNetwork
	daemon *fakeDaemon
	dirs   map[string]string
}

// newHarnessHost points every harness at its own temp dir through the dir
// override variables, so no test touches the real home.
func newHarnessHost(t *testing.T) *harnessHost {
	root := t.TempDir()
	dirs := map[string]string{
		"CLAUDE_CONFIG_DIR":   filepath.Join(root, "claude"),
		"CODEX_HOME":          filepath.Join(root, "codex"),
		"XDG_CONFIG_HOME":     filepath.Join(root, "xdg"),
		"PI_CODING_AGENT_DIR": filepath.Join(root, "pi"),
	}
	daemon := &fakeDaemon{info: &proto.GetAgentNetworkInfoResponse{
		State:    proto.GetAgentNetworkInfoResponse_OK,
		Endpoint: testEndpoint + "/",
		Providers: []*proto.AgentNetworkProvider{
			{Id: "p-anthropic", Name: "Anthropic", CatalogId: "anthropic", Models: []string{"claude-opus-5", "claude-sonnet-5"}},
			{Id: "p-openai", Name: "OpenAI", CatalogId: "openai", AllModelsAllowed: true},
			{Id: "p-vertex", Name: "Vertex", CatalogId: "vertex_ai_api"},
		},
	}}
	svc := NewAgentNetwork(fakeConn{cli: daemon})
	svc.harnessEnv = func() (harness.Env, error) {
		return harness.Env{
			GOOS:       runtime.GOOS,
			Home:       filepath.Join(root, "home"),
			Getenv:     func(k string) string { return dirs[k] },
			RecordPath: filepath.Join(root, "record.json"),
		}, nil
	}
	return &harnessHost{svc: svc, daemon: daemon, dirs: dirs}
}

func (h *harnessHost) claudeSettings() string {
	return filepath.Join(h.dirs["CLAUDE_CONFIG_DIR"], "settings.json")
}

func findHarness(t *testing.T, list []AgentNetworkHarness, id string) AgentNetworkHarness {
	t.Helper()
	for _, h := range list {
		if h.ID == id {
			return h
		}
	}
	require.Failf(t, "harness missing", "%s not listed", id)
	return AgentNetworkHarness{}
}

func providerIDs(ps []HarnessProvider) []string {
	ids := make([]string, 0, len(ps))
	for _, p := range ps {
		ids = append(ids, p.ID)
	}
	return ids
}

func TestHarnessesListsProvidersEachHarnessCanUse(t *testing.T) {
	h := newHarnessHost(t)
	list, err := h.svc.Harnesses(context.Background())
	require.NoError(t, err)
	require.Len(t, list, len(harness.All()))

	claude := findHarness(t, list, "claude-code")
	assert.Equal(t, harnessNotConfigured, claude.Status)
	assert.Equal(t, []string{h.claudeSettings()}, claude.Files, "files resolve through the dir override")
	assert.Equal(t, []string{"p-anthropic", "p-vertex"}, providerIDs(claude.Providers), "claude-code speaks anthropic and vertex")
	assert.Equal(t, "claude-opus-5", claude.Providers[0].DefaultModel, "the provider's first model is the default")
	assert.False(t, claude.Providers[0].NeedsVertexProject)
	assert.True(t, claude.Providers[1].NeedsVertexProject, "vertex needs a GCP project")

	codex := findHarness(t, list, "codex")
	assert.Equal(t, []string{"p-openai"}, providerIDs(codex.Providers))
	assert.Empty(t, codex.Providers[0].DefaultModel, "codex has no default model, it picks its own")

	pi := findHarness(t, list, "pi")
	assert.Len(t, pi.Files, 2, "pi writes two files")
	require.Equal(t, []string{"p-anthropic", "p-openai"}, providerIDs(pi.Providers))
	assert.Equal(t, "gpt-5.5", pi.Providers[1].DefaultModel, "a provider without models falls back to the variant default")
}

func TestHarnessesWithoutAccessStillReportsStatus(t *testing.T) {
	h := newHarnessHost(t)
	h.daemon.info = &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_NOT_ENABLED}

	list, err := h.svc.Harnesses(context.Background())
	require.NoError(t, err)
	for _, hn := range list {
		assert.Equal(t, harnessNotConfigured, hn.Status, hn.ID)
		assert.Empty(t, hn.Providers, "%s offers no provider without access", hn.ID)
	}
}

func TestPlanApplyUndoClaudeCode(t *testing.T) {
	h := newHarnessHost(t)
	ctx := context.Background()
	require.NoError(t, os.MkdirAll(h.dirs["CLAUDE_CONFIG_DIR"], 0o700))
	original := `{"theme": "dark"}`
	require.NoError(t, os.WriteFile(h.claudeSettings(), []byte(original), 0o600))
	req := HarnessSetup{Harness: "claude-code", Provider: "p-anthropic", Model: "claude-sonnet-5"}

	plan, err := h.svc.PlanHarness(ctx, req)
	require.NoError(t, err)
	assert.True(t, plan.Pending)
	assert.False(t, plan.Conflict)
	got := map[string]HarnessChange{}
	for _, c := range plan.Changes {
		got[c.Key] = c
	}
	assert.Equal(t, HarnessChange{
		File: h.claudeSettings(), Key: "env.ANTHROPIC_BASE_URL", Action: "set", After: `"` + testEndpoint + `"`,
	}, got["env.ANTHROPIC_BASE_URL"], "endpoint is set without its trailing slash")
	assert.Equal(t, `"claude-sonnet-5"`, got["model"].After)
	data, err := os.ReadFile(h.claudeSettings())
	require.NoError(t, err)
	assert.Equal(t, original, string(data), "a plan writes nothing")

	applied, err := h.svc.ApplyHarness(ctx, req, false)
	require.NoError(t, err)
	assert.Len(t, applied.Backups, 1, "the existing file is backed up")
	data, err = os.ReadFile(h.claudeSettings())
	require.NoError(t, err)
	assert.Contains(t, string(data), testEndpoint)
	assert.Contains(t, string(data), `"theme": "dark"`, "unrelated keys survive")

	list, err := h.svc.Harnesses(ctx)
	require.NoError(t, err)
	assert.Equal(t, harnessConfigured, findHarness(t, list, "claude-code").Status)

	undone, err := h.svc.UndoHarness("claude-code")
	require.NoError(t, err)
	for _, c := range undone.Changes {
		assert.Equal(t, "restore", c.Action, c.Key)
	}
	data, err = os.ReadFile(h.claudeSettings())
	require.NoError(t, err)
	assert.JSONEq(t, original, string(data), "undo restores the file")

	list, err = h.svc.Harnesses(ctx)
	require.NoError(t, err)
	assert.Equal(t, harnessNotConfigured, findHarness(t, list, "claude-code").Status)
}

func TestApplyConflictNeedsForce(t *testing.T) {
	h := newHarnessHost(t)
	ctx := context.Background()
	require.NoError(t, os.MkdirAll(h.dirs["CLAUDE_CONFIG_DIR"], 0o700))
	original := `{"env": {"ANTHROPIC_BASE_URL": "https://mine.example"}}`
	require.NoError(t, os.WriteFile(h.claudeSettings(), []byte(original), 0o600))
	req := HarnessSetup{Harness: "claude-code", Provider: "p-anthropic"}

	plan, err := h.svc.PlanHarness(ctx, req)
	require.NoError(t, err, "a conflict is reported in the plan, not as an error")
	assert.True(t, plan.Conflict)
	var conflicted []string
	for _, c := range plan.Changes {
		if c.Conflict {
			conflicted = append(conflicted, c.Key)
			assert.Equal(t, `"https://mine.example"`, c.Before)
		}
	}
	assert.Equal(t, []string{"env.ANTHROPIC_BASE_URL"}, conflicted)

	_, err = h.svc.ApplyHarness(ctx, req, false)
	require.ErrorIs(t, err, harness.ErrConflict)
	data, err := os.ReadFile(h.claudeSettings())
	require.NoError(t, err)
	assert.Equal(t, original, string(data), "a refused apply writes nothing")

	_, err = h.svc.ApplyHarness(ctx, req, true)
	require.NoError(t, err)
	_, err = h.svc.UndoHarness("claude-code")
	require.NoError(t, err)
	data, err = os.ReadFile(h.claudeSettings())
	require.NoError(t, err)
	assert.JSONEq(t, original, string(data), "undo puts the user's value back")
}

func TestPlanUnparseableFileGivesSnippet(t *testing.T) {
	h := newHarnessHost(t)
	file := filepath.Join(h.dirs["XDG_CONFIG_HOME"], "opencode", "opencode.jsonc")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o700))
	require.NoError(t, os.WriteFile(file, []byte("{\n  // mine\n}\n"), 0o600))

	plan, err := h.svc.PlanHarness(context.Background(), HarnessSetup{Harness: "opencode", Provider: "p-openai", Model: "gpt-5.5"})
	require.NoError(t, err)
	assert.Equal(t, file, plan.Unparseable)
	assert.Empty(t, plan.Changes)
	require.Len(t, plan.Snippets, 1)
	assert.Equal(t, file, plan.Snippets[0].File)
	assert.Contains(t, plan.Snippets[0].Content, testEndpoint+"/v1")
}

func TestPlanRejectsBadRequests(t *testing.T) {
	cases := map[string]struct {
		req   HarnessSetup
		state proto.GetAgentNetworkInfoResponse_State
	}{
		"unknown harness":        {req: HarnessSetup{Harness: "cursor", Provider: "p-anthropic"}},
		"unknown provider":       {req: HarnessSetup{Harness: "claude-code", Provider: "p-nope"}},
		"incompatible provider":  {req: HarnessSetup{Harness: "codex", Provider: "p-anthropic"}},
		"model not allowed":      {req: HarnessSetup{Harness: "claude-code", Provider: "p-anthropic", Model: "gpt-5.5"}},
		"vertex without project": {req: HarnessSetup{Harness: "claude-code", Provider: "p-vertex"}},
		"no user": {
			req:   HarnessSetup{Harness: "claude-code", Provider: "p-anthropic"},
			state: proto.GetAgentNetworkInfoResponse_NO_USER,
		},
		"server too old": {
			req:   HarnessSetup{Harness: "claude-code", Provider: "p-anthropic"},
			state: proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarnessHost(t)
			if tc.state != proto.GetAgentNetworkInfoResponse_OK {
				h.daemon.info.State = tc.state
			}
			_, err := h.svc.PlanHarness(context.Background(), tc.req)
			assert.Error(t, err)
			_, err = h.svc.ApplyHarness(context.Background(), tc.req, true)
			assert.Error(t, err)
			_, statErr := os.Stat(h.claudeSettings())
			assert.ErrorIs(t, statErr, os.ErrNotExist, "nothing is written")
		})
	}
}

func TestUndoNothingConfigured(t *testing.T) {
	h := newHarnessHost(t)
	plan, err := h.svc.UndoHarness("codex")
	require.NoError(t, err)
	assert.Empty(t, plan.Changes)
	assert.False(t, plan.Pending)
}
