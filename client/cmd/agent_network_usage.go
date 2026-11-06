package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/netbirdio/netbird/client/proto"
)

const (
	agentNetworkNoUserText = "Agent Networks usage is not available for this peer " +
		"(it was added with a setup key and has no user)."
	agentNetworkNotEnabledText  = "Agent Networks is not enabled for your NetBird account."
	agentNetworkNoProvidersText = "No Agent Networks policy gives you access. Ask your administrator."
	agentNetworkBlockedText     = "Your NetBird user is blocked or waiting for approval, " +
		"so Agent Networks is not available. Ask your administrator."
	agentNetworkUnsupportedText = "Your NetBird management server does not report Agent Networks usage. " +
		"Ask your administrator to upgrade it."
	agentNetworkNotConnectedText = "NetBird is not connected. Run `netbird up` first."
	agentNetworkLoginExpiredText = "Your NetBird login expired. " +
		"Run `netbird up` to sign in again before using Agent Networks."
)

var agentNetworkUsageJSON bool

var agentNetworkUsageCmd = &cobra.Command{
	Use:     "usage",
	Short:   "Show your remaining Agent Networks allowance",
	Long:    "Show, per provider, the limits that apply to you on this peer, how much of each you used, and when each resets.",
	Example: "  netbird agent-network usage\n  netbird agent-network usage --json",
	Args:    cobra.NoArgs,
	RunE:    agentNetworkUsage,
}

func init() {
	agentNetworkUsageCmd.Flags().BoolVar(&agentNetworkUsageJSON, "json", false, "print the daemon response as JSON")
	agentNetworkCmd.AddCommand(agentNetworkUsageCmd)
}

func agentNetworkUsage(cmd *cobra.Command, _ []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	resp, err := proto.NewDaemonServiceClient(conn).GetAgentNetworkInfo(cmd.Context(), &proto.GetAgentNetworkInfoRequest{})
	if err != nil {
		return agentNetworkInfoError(err)
	}
	return renderAgentNetworkUsage(cmd.OutOrStdout(), resp, agentNetworkUsageJSON)
}

// agentNetworkInfoError turns the daemon's "client is not running" refusal
// into the action the user has to take.
func agentNetworkInfoError(err error) error {
	if gstatus.Code(err) == codes.FailedPrecondition {
		return errors.New(agentNetworkNotConnectedText)
	}
	return daemonCallError("get Agent Networks info", err)
}

func renderAgentNetworkUsage(w io.Writer, resp *proto.GetAgentNetworkInfoResponse, asJSON bool) error {
	if resp.GetState() == proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED {
		return errors.New(agentNetworkUnsupportedText)
	}
	if asJSON {
		return writeAgentNetworkJSON(w, resp)
	}

	switch resp.GetState() {
	case proto.GetAgentNetworkInfoResponse_OK:
		writeAgentNetworkProviders(w, resp)
	case proto.GetAgentNetworkInfoResponse_NO_USER:
		fmt.Fprintln(w, agentNetworkNoUserText)
	case proto.GetAgentNetworkInfoResponse_NOT_ENABLED:
		fmt.Fprintln(w, agentNetworkNotEnabledText)
	case proto.GetAgentNetworkInfoResponse_USER_BLOCKED:
		fmt.Fprintln(w, agentNetworkBlockedText)
	default:
		return fmt.Errorf("unexpected Agent Networks state %s", resp.GetState())
	}

	if resp.GetLoginExpired() {
		fmt.Fprintf(w, "\n%s\n", agentNetworkLoginExpiredText)
	}
	return nil
}

func writeAgentNetworkJSON(w io.Writer, resp *proto.GetAgentNetworkInfoResponse) error {
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	// protojson randomizes its whitespace; re-indent for stable output.
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return fmt.Errorf("indent response: %w", err)
	}
	out.WriteByte('\n')
	_, err = w.Write(out.Bytes())
	return err
}

func writeAgentNetworkProviders(w io.Writer, resp *proto.GetAgentNetworkInfoResponse) {
	if len(resp.GetProviders()) == 0 {
		fmt.Fprintln(w, agentNetworkNoProvidersText)
		return
	}

	// Reset times are relative to when management computed the answer, so
	// the numbers and the countdown describe the same moment.
	now := time.Now()
	if resp.GetComputedAt() != nil {
		now = resp.GetComputedAt().AsTime()
	}

	fmt.Fprintf(w, "Agent Networks usage for %s\n", resp.GetUserEmail())
	for _, p := range resp.GetProviders() {
		fmt.Fprintf(w, "\n%s (%s)", p.GetName(), p.GetCatalogId())
		if p.GetExhausted() {
			fmt.Fprint(w, " - exhausted, requests are refused until a limit resets")
		}
		fmt.Fprintln(w)

		switch {
		case len(p.GetLimits()) > 0:
			writeAgentNetworkLimits(w, p.GetLimits(), now)
		case p.GetUnlimited():
			fmt.Fprintln(w, "  Unlimited")
		default:
			fmt.Fprintln(w, "  No limits apply")
		}
	}
}

func writeAgentNetworkLimits(w io.Writer, limits []*proto.AgentNetworkLimit, now time.Time) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  LIMIT\tAPPLIES TO\tUSED / CAP\tREMAINING\tRESETS")
	for _, l := range limits {
		remaining := l.GetCap() - l.GetUsed()
		if remaining < 0 {
			remaining = 0
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s / %s\t%s\t%s\n",
			limitSourceLabel(l),
			limitScopeLabel(l),
			formatLimitAmount(l.GetUnit(), l.GetUsed(), false),
			formatLimitAmount(l.GetUnit(), l.GetCap(), true),
			formatLimitAmount(l.GetUnit(), remaining, true),
			formatLimitReset(l, now),
		)
	}
	_ = tw.Flush()
}

func limitSourceLabel(l *proto.AgentNetworkLimit) string {
	name := l.GetSourceName()
	if name == "" {
		name = l.GetSourceId()
	}
	if l.GetSource() == proto.AgentNetworkLimit_ACCOUNT_RULE {
		return fmt.Sprintf("account rule %q", name)
	}
	return fmt.Sprintf("policy %q", name)
}

func limitScopeLabel(l *proto.AgentNetworkLimit) string {
	if l.GetScope() != proto.AgentNetworkLimit_GROUP {
		return "you"
	}
	name := l.GetGroupName()
	if name == "" {
		name = l.GetGroupId()
	}
	return "group " + name
}

func formatLimitAmount(unit proto.AgentNetworkLimit_Unit, v float64, withUnit bool) string {
	if unit == proto.AgentNetworkLimit_USD {
		return fmt.Sprintf("$%.2f", v)
	}
	s := groupThousands(int64(v))
	if withUnit {
		s += " tokens"
	}
	return s
}

func groupThousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func formatLimitReset(l *proto.AgentNetworkLimit, now time.Time) string {
	if l.GetResetsAt() == nil {
		return "-"
	}
	at := l.GetResetsAt().AsTime()
	return fmt.Sprintf("in %s (%s)", formatUntil(at.Sub(now)), at.Local().Format("2006-01-02 15:04 MST"))
}

func formatUntil(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	days := int(d / (24 * time.Hour))
	hours := int(d % (24 * time.Hour) / time.Hour)
	minutes := int(d % time.Hour / time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}
