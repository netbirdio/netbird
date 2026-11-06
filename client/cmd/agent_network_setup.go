package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/agentnetwork/harness"
	"github.com/netbirdio/netbird/client/proto"
)

const anSetupEndpointTimeout = 10 * time.Second

var (
	anSetupProvider      string
	anSetupModel         string
	anSetupVertexProject string
	anSetupDryRun        bool
	anSetupPrint         bool
	anSetupForce         bool
)

var agentNetworkSetupCmd = &cobra.Command{
	Use:   "setup <harness>",
	Short: "Point a coding agent at Agent Networks",
	Long: "Write a coding agent's global user config so it sends model requests to your Agent Networks endpoint.\n" +
		"No credential is written: the endpoint authorizes this machine by its NetBird identity.\n" +
		"Run 'netbird agent-network setup list' for the supported agents.",
	Example: "  netbird agent-network setup claude-code --dry-run\n" +
		"  netbird agent-network setup claude-code --provider anthropic --model claude-opus-5\n" +
		"  netbird agent-network setup undo claude-code",
	Args: cobra.ExactArgs(1),
	RunE: anSetupRun,
}

var agentNetworkSetupUndoCmd = &cobra.Command{
	Use:   "undo <harness>",
	Short: "Revert the settings setup wrote",
	Long:  "Restore every key setup wrote to its previous value. A key changed since is reported and left alone.",
	Args:  cobra.ExactArgs(1),
	RunE:  anSetupUndo,
}

var agentNetworkSetupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the supported agents and whether each is set up",
	Args:  cobra.NoArgs,
	RunE:  anSetupList,
}

func init() {
	f := agentNetworkSetupCmd.Flags()
	f.StringVar(&anSetupProvider, "provider", "", "provider to use, by name, id or catalog id (default: the first one the agent can use)")
	f.StringVar(&anSetupModel, "model", "", "model to use (default: the provider's first model)")
	f.StringVar(&anSetupVertexProject, "vertex-project", "", "GCP project id, required for a Vertex AI provider")
	f.BoolVar(&anSetupDryRun, "dry-run", false, "show the changes without writing anything")
	f.BoolVar(&anSetupPrint, "print", false, "print the settings to add by hand instead of writing them")
	f.BoolVar(&anSetupForce, "force", false, "overwrite keys that hold values NetBird did not write")
	agentNetworkSetupUndoCmd.Flags().BoolVar(&anSetupDryRun, "dry-run", false, "show the changes without writing anything")

	agentNetworkSetupCmd.AddCommand(agentNetworkSetupUndoCmd, agentNetworkSetupListCmd)
	agentNetworkCmd.AddCommand(agentNetworkSetupCmd)
}

func anSetupRun(cmd *cobra.Command, args []string) error {
	def, err := harness.Lookup(args[0])
	if err != nil {
		return err
	}
	info, err := anSetupFetchInfo(cmd)
	if err != nil {
		return err
	}
	if err := anSetupCheckState(cmd, info); err != nil {
		return err
	}
	provider, variant, err := anSetupPickProvider(def, info.GetProviders(), anSetupProvider)
	if err != nil {
		return err
	}
	model, err := anSetupPickModel(cmd, def, provider, variant, anSetupModel)
	if err != nil {
		return err
	}

	env, err := anSetupEnv()
	if err != nil {
		return err
	}
	settings, err := def.Render(variant, map[harness.Var]string{
		harness.VarEndpoint:      strings.TrimRight(info.GetEndpoint(), "/"),
		harness.VarModel:         model,
		harness.VarVertexProject: anSetupVertexProject,
	}, env)
	var missing *harness.MissingVarError
	if errors.As(err, &missing) {
		return fmt.Errorf("provider %q needs --%s", provider.GetName(), strings.ReplaceAll(string(missing.Var), "_", "-"))
	}
	if err != nil {
		return err
	}

	if err := anSetupCheckEndpoint(cmd.Context(), info.GetEndpoint()); err != nil {
		cmd.PrintErrf("Warning: %v\n", err)
	}

	if anSetupPrint {
		return anSetupPrintFragments(cmd, settings)
	}
	return anSetupApply(cmd, def, settings, env)
}

func anSetupApply(cmd *cobra.Command, def *harness.Definition, settings []harness.Setting, env harness.Env) error {
	rec, err := harness.LoadRecord(env.RecordPath)
	if err != nil {
		return fmt.Errorf("read setup record: %w", err)
	}
	plan, err := harness.NewPlan(def.ID, settings, rec, anSetupForce)
	var unparseable *harness.UnparseableError
	if errors.As(err, &unparseable) {
		cmd.PrintErrf("%v\nNetBird only rewrites strict JSON. Add these settings by hand:\n\n", err)
		if perr := anSetupPrintFragments(cmd, settings); perr != nil {
			return perr
		}
		return errors.New("settings not written")
	}
	if plan == nil {
		return err
	}

	anSetupPrintChanges(cmd, plan)
	if errors.Is(err, harness.ErrConflict) {
		return errors.New("keys marked (!) hold values NetBird did not write; rerun with --force to replace them, undo restores them")
	}
	if err != nil {
		return err
	}
	if !plan.Pending() {
		cmd.Printf("%s is already set up.\n", def.Name)
		return nil
	}
	if anSetupDryRun {
		cmd.Println("Dry run: nothing was written.")
		return nil
	}

	backups, err := plan.Apply(rec, env.RecordPath, time.Now())
	for _, b := range backups {
		cmd.Printf("Backup: %s\n", b)
	}
	if err != nil {
		return err
	}
	cmd.Printf("%s is set up for Agent Networks.\n", def.Name)
	if def.Notice != "" {
		cmd.Println(def.Notice)
	}
	return nil
}

func anSetupUndo(cmd *cobra.Command, args []string) error {
	def, err := harness.Lookup(args[0])
	if err != nil {
		return err
	}
	env, err := anSetupEnv()
	if err != nil {
		return err
	}
	rec, err := harness.LoadRecord(env.RecordPath)
	if err != nil {
		return fmt.Errorf("read setup record: %w", err)
	}
	plan, err := harness.NewPlan(def.ID, nil, rec, false)
	if err != nil {
		return err
	}
	if len(plan.Changes) == 0 {
		cmd.Printf("Nothing to undo for %s.\n", def.Name)
		return nil
	}
	anSetupPrintChanges(cmd, plan)
	if anSetupDryRun {
		cmd.Println("Dry run: nothing was written.")
		return nil
	}
	backups, err := plan.Apply(rec, env.RecordPath, time.Now())
	for _, b := range backups {
		cmd.Printf("Backup: %s\n", b)
	}
	if err != nil {
		return err
	}
	cmd.Printf("%s no longer uses Agent Networks.\n", def.Name)
	return nil
}

func anSetupList(cmd *cobra.Command, _ []string) error {
	env, err := anSetupEnv()
	if err != nil {
		return err
	}
	rec, err := harness.LoadRecord(env.RecordPath)
	if err != nil {
		return fmt.Errorf("read setup record: %w", err)
	}
	for _, def := range harness.All() {
		cmd.Printf("%-14s %-14s %s (%s)\n", def.ID, def.Name, harness.Status(def.ID, rec), def.Files[0].Path(env))
	}
	return nil
}

func anSetupEnv() (harness.Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return harness.Env{}, fmt.Errorf("find home directory: %w", err)
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return harness.Env{}, fmt.Errorf("find config directory: %w", err)
	}
	return harness.Env{
		GOOS:       runtime.GOOS,
		Home:       home,
		Getenv:     os.Getenv,
		RecordPath: filepath.Join(cfg, "netbird", "agent-network-setup.json"),
	}, nil
}

func anSetupFetchInfo(cmd *cobra.Command) (*proto.GetAgentNetworkInfoResponse, error) {
	conn, err := getClient(cmd)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	info, err := proto.NewDaemonServiceClient(conn).GetAgentNetworkInfo(cmd.Context(), &proto.GetAgentNetworkInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("get Agent Networks info: %s", status.Convert(err).Message())
	}
	return info, nil
}

// anSetupCheckState refuses every state but OK, an unknown one included.
func anSetupCheckState(cmd *cobra.Command, info *proto.GetAgentNetworkInfoResponse) error {
	if info.GetLoginExpired() {
		cmd.PrintErrln("Your NetBird login expired. Run `netbird up` to sign in again before using Agent Networks.")
	}
	switch info.GetState() {
	case proto.GetAgentNetworkInfoResponse_OK:
		if info.GetEndpoint() == "" {
			return errors.New("management reported no Agent Networks endpoint")
		}
		return nil
	case proto.GetAgentNetworkInfoResponse_NO_USER:
		return errors.New("not available for this peer: Agent Networks needs a peer owned by a user, and this one was registered with a setup key")
	case proto.GetAgentNetworkInfoResponse_NOT_ENABLED:
		return errors.New("this account has no Agent Network enabled")
	case proto.GetAgentNetworkInfoResponse_USER_BLOCKED:
		return errors.New("not available: your NetBird user is blocked or pending approval")
	case proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED:
		return errors.New("the management server is too old to report Agent Networks access")
	default:
		return fmt.Errorf("unknown Agent Networks state %s", info.GetState())
	}
}

// anSetupPickProvider returns the requested provider, or the first one the
// harness can drive.
func anSetupPickProvider(def *harness.Definition, providers []*proto.AgentNetworkProvider, want string) (*proto.AgentNetworkProvider, harness.Variant, error) {
	if len(providers) == 0 {
		return nil, harness.Variant{}, errors.New("no Agent Networks provider is available to this peer yet: ask your administrator for a policy")
	}
	var names []string
	for _, p := range providers {
		flavor := p.GetApiFlavor()
		if flavor == "" {
			flavor = p.GetCatalogId()
		}
		names = append(names, fmt.Sprintf("%s (%s)", p.GetName(), flavor))
	}

	if want != "" {
		for _, p := range providers {
			if want != p.GetName() && want != p.GetId() && want != p.GetCatalogId() {
				continue
			}
			v, ok := def.Variant(p.GetCatalogId(), p.GetApiFlavor())
			if !ok {
				return nil, harness.Variant{}, fmt.Errorf("%s cannot use provider %q: it speaks the %s API", def.Name, p.GetName(), p.GetApiFlavor())
			}
			return p, v, nil
		}
		return nil, harness.Variant{}, fmt.Errorf("no provider %q, available: %s", want, strings.Join(names, ", "))
	}

	for _, p := range providers {
		if v, ok := def.Variant(p.GetCatalogId(), p.GetApiFlavor()); ok {
			return p, v, nil
		}
	}
	return nil, harness.Variant{}, fmt.Errorf("%s cannot use any provider available to you: %s", def.Name, strings.Join(names, ", "))
}

// anSetupPickModel returns the requested model, else the provider's first,
// else the variant default; empty leaves the choice to the harness.
func anSetupPickModel(cmd *cobra.Command, def *harness.Definition, p *proto.AgentNetworkProvider, v harness.Variant, want string) (string, error) {
	cmd.Printf("Provider: %s\n", p.GetName())
	models := p.GetModels()
	switch {
	case want != "":
		if !p.GetAllModelsAllowed() && len(models) > 0 && !slices.Contains(models, want) {
			return "", fmt.Errorf("model %q is not allowed on %s, allowed: %s", want, p.GetName(), strings.Join(models, ", "))
		}
		cmd.Printf("Model: %s\n", want)
		return want, nil
	case len(models) > 0:
		cmd.Printf("Model: %s (the provider's first model, pass --model to choose another)\n", models[0])
		return models[0], nil
	case v.DefaultModel != "":
		cmd.Printf("Model: %s (default, pass --model to choose another)\n", v.DefaultModel)
		return v.DefaultModel, nil
	default:
		cmd.Printf("Model: chosen by %s (pass --model to pin one)\n", def.Name)
		return "", nil
	}
}

// anSetupCheckEndpoint makes one request to the endpoint with TLS verified.
// Any HTTP answer proves the overlay path.
func anSetupCheckEndpoint(ctx context.Context, endpoint string) error {
	ctx, cancel := context.WithTimeout(ctx, anSetupEndpointTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/", nil)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		return nil
	}
	var verr *tls.CertificateVerificationError
	var uerr x509.UnknownAuthorityError
	if errors.As(err, &verr) || errors.As(err, &uerr) {
		return fmt.Errorf("the endpoint's TLS certificate is not trusted: %w. "+
			"If it is issued by a private CA, Node-based agents such as Claude Code need NODE_EXTRA_CA_CERTS set to that CA", err)
	}
	return fmt.Errorf("the endpoint did not answer over NetBird, check 'netbird status': %w", err)
}

func anSetupPrintFragments(cmd *cobra.Command, settings []harness.Setting) error {
	frags, err := harness.Fragments(settings)
	if err != nil {
		return err
	}
	for _, file := range harness.SortedFiles(frags) {
		cmd.Printf("Add to %s:\n%s\n", file, frags[file])
	}
	return nil
}

func anSetupPrintChanges(cmd *cobra.Command, plan *harness.Plan) {
	file := ""
	for _, c := range plan.Changes {
		if c.File != file {
			file = c.File
			cmd.Printf("%s:\n", file)
		}
		mark := " "
		if c.Conflict {
			mark = "!"
		}
		line := fmt.Sprintf("  %s %-7s %s: %s -> %s", mark, c.Action, harness.PathString(c.Path), anSetupValue(c.Before), anSetupValue(c.After))
		if c.Action == harness.ActionKeep {
			line = fmt.Sprintf("  %s %-7s %s: %s (changed since NetBird wrote it, left alone)", mark, c.Action, harness.PathString(c.Path), anSetupValue(c.Before))
		}
		cmd.Println(line)
	}
}

func anSetupValue(raw []byte) string {
	if raw == nil {
		return "(absent)"
	}
	return string(raw)
}
