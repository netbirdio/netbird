package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/netbirdio/netbird/client/proto"
)

// agentNetworkAuthToken is the placeholder credential exported for
// AI-tool CLIs: the Agent Network proxy authenticates callers by tunnel
// peer and injects the real upstream credentials itself, so the
// client-side token only needs to satisfy the tool's non-empty check.
const agentNetworkAuthToken = "netbird"

var (
	agentNetworkProviderFlag string
	agentNetworkModelFlag    string
	agentNetworkJSONFlag     bool
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
	Long: `Print POSIX shell export lines that configure AI tools to use the Agent Network proxy.
The variables depend on the provider's API shape — Anthropic API, AWS Bedrock, Google Vertex AI,
and OpenAI-compatible providers each get the environment their tools expect (for Claude Code,
following its LLM-gateway configuration). Apply them to the current shell with:

  eval "$(netbird agent-network env)"

When several providers are authorized, pass --provider to pick one; when several models are
allowed, pass --model to pin one — nothing is ever guessed.`,
	Example: "  eval \"$(netbird agent-network env)\"\n  eval \"$(netbird agent-network env --provider 'Bedrock prod' --model anthropic.claude-sonnet-4-5)\"",
	RunE:    agentNetworkEnv,
}

func init() {
	agentNetworkLsCmd.PersistentFlags().BoolVar(&agentNetworkJSONFlag, "json", false, "output the setup as JSON")
	agentNetworkEnvCmd.PersistentFlags().StringVar(&agentNetworkProviderFlag, "provider", "", "provider to configure, by name or catalog id (required when several are authorized)")
	agentNetworkEnvCmd.PersistentFlags().StringVar(&agentNetworkModelFlag, "model", "", "model to export (required when several models are allowed)")
}

// fetchAgentNetworkSetup asks the daemon for the caller-scoped Agent
// Network setup. The daemon relays the request to management over its
// existing peer connection, so no elevated permissions are needed.
func fetchAgentNetworkSetup(cmd *cobra.Command) (*proto.GetAgentNetworkSetupResponse, error) {
	conn, err := getClient(cmd)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	setup, err := client.GetAgentNetworkSetup(cmd.Context(), &proto.GetAgentNetworkSetupRequest{})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.Unimplemented {
			return nil, fmt.Errorf("the running daemon does not support agent-network commands — update the NetBird daemon and restart the service")
		}
		return nil, fmt.Errorf("get agent network setup: %v", status.Convert(err).Message())
	}
	return setup, nil
}

func agentNetworkLs(cmd *cobra.Command, _ []string) error {
	setup, err := fetchAgentNetworkSetup(cmd)
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
	cmd.Println("To configure an AI tool in the current shell: eval \"$(netbird agent-network env)\"")
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

func providerFlavorLabel(p *proto.AgentNetworkProvider) string {
	if p.ApiFlavor == "" {
		return p.CatalogId
	}
	return fmt.Sprintf("%s · %s-flavor API", p.CatalogId, p.ApiFlavor)
}

func agentNetworkEnv(cmd *cobra.Command, _ []string) error {
	setup, err := fetchAgentNetworkSetup(cmd)
	if err != nil {
		return err
	}

	if !setup.Configured {
		// An answer, not an error: print nothing eval-able and say why on
		// stderr so `eval "$(...)"` stays a harmless no-op.
		cmd.PrintErrln("Agent Network is not available for this peer. Ask your administrator.")
		return nil
	}

	lines, err := buildAgentNetworkEnv(setup, agentNetworkProviderFlag, agentNetworkModelFlag)
	if err != nil {
		return err
	}
	for _, line := range lines {
		cmd.Println(line)
	}
	return nil
}

// buildAgentNetworkEnv renders the export lines for one selected
// provider. Nothing is guessed: an ambiguous provider or model choice
// comes back as comment lines instead of exports, and an invalid
// --provider/--model is an error.
func buildAgentNetworkEnv(setup *proto.GetAgentNetworkSetupResponse, providerFlag, modelFlag string) ([]string, error) {
	provider, choiceLines, err := selectAgentNetworkProvider(setup.Providers, providerFlag)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return choiceLines, nil
	}

	model, modelNotes, err := resolveAgentNetworkModel(provider, modelFlag)
	if err != nil {
		return nil, err
	}

	var lines []string
	switch {
	case provider.CatalogId == "bedrock_api":
		// Claude Code's Bedrock-format gateway configuration: the proxy
		// routes native Bedrock paths and injects the AWS credentials, so
		// client-side signing is skipped.
		lines = append(lines,
			exportLine("CLAUDE_CODE_USE_BEDROCK", "1"),
			exportLine("ANTHROPIC_BEDROCK_BASE_URL", setup.Endpoint),
			exportLine("CLAUDE_CODE_SKIP_BEDROCK_AUTH", "1"),
		)
		if model != "" {
			lines = append(lines, exportLine("ANTHROPIC_MODEL", model))
		}
	case provider.CatalogId == "vertex_ai_api":
		// Claude Code's Vertex-format gateway configuration. Vertex
		// requests carry the GCP project and region in the URL path, which
		// the proxy forwards to the upstream — those two values belong to
		// the operator's GCP setup and must come from the administrator.
		lines = append(lines,
			exportLine("CLAUDE_CODE_USE_VERTEX", "1"),
			exportLine("ANTHROPIC_VERTEX_BASE_URL", setup.Endpoint),
			exportLine("CLAUDE_CODE_SKIP_VERTEX_AUTH", "1"),
		)
		if model != "" {
			lines = append(lines, exportLine("ANTHROPIC_MODEL", model))
		}
		lines = append(lines,
			comment("Vertex requests carry your operator's GCP project and region in the URL."),
			comment("Ask your administrator for the values, then export:"),
			comment("  export ANTHROPIC_VERTEX_PROJECT_ID=<project>"),
			comment("  export CLOUD_ML_REGION=<region>"),
		)
	case provider.ApiFlavor == "anthropic":
		lines = append(lines,
			exportLine("ANTHROPIC_BASE_URL", setup.Endpoint),
			exportLine("ANTHROPIC_AUTH_TOKEN", agentNetworkAuthToken),
		)
		if model != "" {
			lines = append(lines, exportLine("ANTHROPIC_MODEL", model))
		}
	case provider.ApiFlavor == "openai":
		lines = append(lines,
			exportLine("OPENAI_BASE_URL", setup.Endpoint),
			exportLine("OPENAI_API_KEY", agentNetworkAuthToken),
		)
		if model != "" {
			lines = append(lines, comment(fmt.Sprintf("Configure your tool to use model %s.", model)))
		}
	default:
		lines = append(lines,
			comment(fmt.Sprintf("Provider %s (%s) is dispatched by URL path; no standard environment", provider.Name, provider.CatalogId)),
			comment("variables apply. Point your tool at the endpoint below (auth token: netbird):"),
			comment("  "+setup.Endpoint),
		)
	}

	for _, note := range modelNotes {
		lines = append(lines, comment(note))
	}
	return lines, nil
}

// selectAgentNetworkProvider picks the provider to configure. An
// explicit --provider matches the operator label or catalog id
// (case-insensitive); with no flag a single authorized provider is
// used, and several come back as comment lines asking for the flag.
func selectAgentNetworkProvider(providers []*proto.AgentNetworkProvider, providerFlag string) (*proto.AgentNetworkProvider, []string, error) {
	if providerFlag != "" {
		wanted := strings.ToLower(strings.TrimSpace(providerFlag))
		for _, p := range providers {
			if strings.ToLower(strings.TrimSpace(p.Name)) == wanted || strings.ToLower(p.CatalogId) == wanted {
				return p, nil, nil
			}
		}
		names := make([]string, 0, len(providers))
		for _, p := range providers {
			names = append(names, fmt.Sprintf("%s (%s)", p.Name, p.CatalogId))
		}
		return nil, nil, fmt.Errorf("provider %q is not authorized for this peer — available: %s", providerFlag, strings.Join(names, ", "))
	}

	if len(providers) == 1 {
		return providers[0], nil, nil
	}

	lines := []string{comment("Multiple providers are authorized — none configured. Re-run with --provider to pick one:")}
	for _, p := range providers {
		lines = append(lines, comment(fmt.Sprintf("  netbird agent-network env --provider %q   (%s)", p.Name, providerFlavorLabel(p))))
	}
	return nil, lines, nil
}

// resolveAgentNetworkModel picks the model for the selected provider. A
// model is never guessed: --model wins (validated against the allowed
// set), a single allowed model is used, and anything ambiguous is
// returned as note lines instead.
func resolveAgentNetworkModel(provider *proto.AgentNetworkProvider, modelFlag string) (string, []string, error) {
	if modelFlag != "" {
		if provider.AllModelsAllowed {
			return modelFlag, nil, nil
		}
		wanted := strings.ToLower(strings.TrimSpace(modelFlag))
		for _, m := range provider.Models {
			if strings.ToLower(strings.TrimSpace(m)) == wanted {
				return modelFlag, nil, nil
			}
		}
		return "", nil, fmt.Errorf("model %q is not allowed on provider %s — run 'netbird agent-network ls' to see the allowed models", modelFlag, provider.Name)
	}

	if len(provider.Models) == 1 && !provider.AllModelsAllowed {
		return provider.Models[0], nil, nil
	}
	if len(provider.Models) == 0 && provider.AllModelsAllowed {
		return "", []string{"Any model is allowed; pass --model to pin one."}, nil
	}

	notes := []string{"Multiple models are allowed — none exported. Re-run with --model to pin one:"}
	for _, m := range provider.Models {
		notes = append(notes, "  "+m)
	}
	if provider.AllModelsAllowed {
		notes = append(notes, "  (any other model the provider serves)")
	}
	return "", notes, nil
}

func exportLine(name, value string) string {
	return fmt.Sprintf("export %s=%s", name, shellQuote(value))
}

func comment(text string) string {
	return "# " + sanitizeOutput(text)
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
