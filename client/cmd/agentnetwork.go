package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// agentNetworkAuthToken is the placeholder credential exported for
// AI-tool CLIs: the Agent Network proxy authenticates callers by tunnel
// peer and injects the real upstream credentials itself, so the
// client-side token only needs to satisfy the tool's non-empty check.
const agentNetworkAuthToken = "netbird"

var (
	agentNetworkModelFlag string
	agentNetworkJSONFlag  bool
)

var agentNetworkCmd = &cobra.Command{
	Use:   "agent-network",
	Short: "Show the Agent Network setup available to this peer",
	Long: `Commands to inspect the Agent Network (AI provider proxy) setup this peer's groups authorize:
the proxy endpoint, the reachable providers, and the allowed models.`,
}

var agentNetworkLsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List the Agent Network endpoint, providers, and allowed models",
	Example: "  netbird agent-network ls",
	RunE:    agentNetworkLs,
}

var agentNetworkEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Print shell export lines that point AI tools at the Agent Network",
	Long: `Print POSIX shell export lines (ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, and
ANTHROPIC_MODEL when unambiguous) that configure Anthropic-compatible AI tools, such as
Claude Code, to use the Agent Network proxy. Apply them to the current shell with:

  eval "$(netbird agent-network env)"

When several models are allowed, none is exported — pass --model to pin one.`,
	Example: "  eval \"$(netbird agent-network env)\"\n  eval \"$(netbird agent-network env --model claude-sonnet-4-5)\"",
	RunE:    agentNetworkEnv,
}

func init() {
	agentNetworkLsCmd.PersistentFlags().BoolVar(&agentNetworkJSONFlag, "json", false, "output the setup as JSON")
	agentNetworkEnvCmd.PersistentFlags().StringVar(&agentNetworkModelFlag, "model", "", "model to export as ANTHROPIC_MODEL (required when several models are allowed)")
}

// fetchAgentNetworkSetup dials the management server directly with the
// active profile's WireGuard key — the same credential and path every
// other peer RPC uses — and asks for the caller-scoped setup. No daemon
// involvement: the request is read-only and needs no tunnel state.
func fetchAgentNetworkSetup(ctx context.Context) (*mgmProto.AgentNetworkSetupResponse, error) {
	pm := profilemanager.NewProfileManager()
	activeProf, err := pm.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %v", err)
	}
	if activeProf == nil {
		return nil, fmt.Errorf("active profile not found, please run 'netbird up' first")
	}

	configFilePath, err := activeProf.FilePath()
	if err != nil {
		return nil, fmt.Errorf("get active profile file path: %v", err)
	}
	config, err := profilemanager.ReadConfig(configFilePath)
	if err != nil {
		// The default profile config (and its WireGuard key) is owned by
		// root; dialing management directly therefore needs the same
		// elevation the daemon has. Point at sudo instead of surfacing a
		// bare permission error.
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("reading profile %s requires elevated permissions — re-run with sudo", configFilePath)
		}
		return nil, fmt.Errorf("read config file %s: %v (run 'netbird up' first)", configFilePath, err)
	}

	privateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse profile private key: %v", err)
	}

	mgmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tlsEnabled := config.ManagementURL.Scheme == "https"
	mgmClient, err := mgm.NewClient(mgmCtx, config.ManagementURL.Host, privateKey, tlsEnabled)
	if err != nil {
		return nil, fmt.Errorf("connect to management service %s: %v", config.ManagementURL.String(), err)
	}
	defer func() {
		_ = mgmClient.Close()
	}()

	setup, err := mgmClient.GetAgentNetworkSetup(mgmCtx)
	if err != nil {
		if s, ok := status.FromError(err); ok {
			switch s.Code() {
			case codes.PermissionDenied:
				return nil, fmt.Errorf("this peer is not registered with the management service at %s — run 'netbird up' first", config.ManagementURL.String())
			case codes.Unimplemented:
				return nil, fmt.Errorf("the management server at %s does not implement the agent-network setup RPC — the process answering runs a build without it.\n"+
					"Verify the running binary contains the RPC: grep -ac GetAgentNetworkSetup <path-to-server-binary> (0 = built without it),\n"+
					"and that this URL actually reaches the server you rebuilt", config.ManagementURL.String())
			}
		}
		return nil, fmt.Errorf("get agent network setup from %s: %v", config.ManagementURL.String(), err)
	}
	return setup, nil
}

func agentNetworkLs(cmd *cobra.Command, _ []string) error {
	setup, err := fetchAgentNetworkSetup(cmd.Context())
	if err != nil {
		return err
	}

	if agentNetworkJSONFlag {
		out, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(setup)
		if err != nil {
			return fmt.Errorf("marshal setup: %v", err)
		}
		cmd.Println(string(out))
		return nil
	}

	if !setup.Configured {
		cmd.Println("Agent Network is not available for this peer. Ask your administrator.")
		return nil
	}

	cmd.Printf("Agent Network endpoint: %s\n", setup.Endpoint)
	cmd.Println("(reachable while connected to NetBird)")
	for _, p := range setup.Providers {
		cmd.Println()
		cmd.Printf("%s (%s)\n", sanitizeOutput(p.Name), sanitizeOutput(providerFlavorLabel(p)))
		switch {
		case p.AllModelsAllowed && len(p.Models) == 0:
			cmd.Println("  All models allowed")
		case p.AllModelsAllowed:
			cmd.Println("  All models allowed, including:")
			printModels(cmd, p.Models)
		default:
			cmd.Println("  Allowed models:")
			printModels(cmd, p.Models)
		}
	}
	cmd.Println()
	cmd.Println("To configure Anthropic-compatible tools in the current shell: eval \"$(netbird agent-network env)\"")
	return nil
}

func printModels(cmd *cobra.Command, models []string) {
	if len(models) == 0 {
		cmd.Println("    (none)")
		return
	}
	for _, m := range models {
		cmd.Printf("    %s\n", sanitizeOutput(m))
	}
}

func providerFlavorLabel(p *mgmProto.AgentNetworkProviderInfo) string {
	if p.ApiFlavor == "" {
		return p.CatalogId
	}
	return fmt.Sprintf("%s · %s-flavor API", p.CatalogId, p.ApiFlavor)
}

func agentNetworkEnv(cmd *cobra.Command, _ []string) error {
	setup, err := fetchAgentNetworkSetup(cmd.Context())
	if err != nil {
		return err
	}

	if !setup.Configured {
		// An answer, not an error: print nothing eval-able and say why on
		// stderr so `eval "$(...)"` stays a harmless no-op.
		cmd.PrintErrln("Agent Network is not available for this peer. Ask your administrator.")
		return nil
	}

	cmd.Printf("export ANTHROPIC_BASE_URL=%s\n", shellQuote(setup.Endpoint))
	cmd.Printf("export ANTHROPIC_AUTH_TOKEN=%s\n", shellQuote(agentNetworkAuthToken))

	model, note, err := resolveAgentNetworkModel(setup, agentNetworkModelFlag)
	if err != nil {
		return err
	}
	if model != "" {
		cmd.Printf("export ANTHROPIC_MODEL=%s\n", shellQuote(model))
	}
	for _, line := range note {
		cmd.Printf("# %s\n", sanitizeOutput(line))
	}
	return nil
}

// resolveAgentNetworkModel picks the model to export from the
// Anthropic-flavor providers' effective model sets. A model is never
// guessed: --model wins (validated against the allowed set), a single
// allowed model is used, and anything ambiguous is returned as comment
// lines instead of an export.
func resolveAgentNetworkModel(setup *mgmProto.AgentNetworkSetupResponse, flagModel string) (string, []string, error) {
	allowAny := false
	var models []string
	seen := make(map[string]struct{})
	for _, p := range setup.Providers {
		if p.ApiFlavor != "anthropic" {
			continue
		}
		if p.AllModelsAllowed {
			allowAny = true
		}
		for _, m := range p.Models {
			key := strings.ToLower(strings.TrimSpace(m))
			if key == "" {
				continue
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			models = append(models, strings.TrimSpace(m))
		}
	}

	if flagModel != "" {
		if allowAny {
			return flagModel, nil, nil
		}
		if _, ok := seen[strings.ToLower(strings.TrimSpace(flagModel))]; !ok {
			return "", nil, fmt.Errorf("model %q is not in the allowed model list — run 'netbird agent-network ls' to see it", flagModel)
		}
		return flagModel, nil, nil
	}

	if len(models) == 0 && !allowAny {
		return "", []string{"No Anthropic-flavor provider is authorized for this peer; ANTHROPIC_MODEL not exported."}, nil
	}
	if len(models) == 1 && !allowAny {
		return models[0], nil, nil
	}

	note := []string{"Multiple models are allowed — none exported. Re-run with --model to pin one:"}
	for _, m := range models {
		note = append(note, "  "+m)
	}
	if allowAny {
		note = append(note, "  (any other model the provider serves)")
	}
	return "", note, nil
}

// shellQuote single-quotes a value for safe use in an eval'd export
// line, escaping embedded single quotes.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// sanitizeOutput strips control characters (including newlines) from
// server-supplied strings so operator-typed values can't break the
// line-oriented output or smuggle lines past a `# ` comment prefix.
func sanitizeOutput(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}
