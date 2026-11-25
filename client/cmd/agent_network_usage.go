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
	agentNetworkNotEnabledText  = "Agent Networks is not enabled for your NetBird account."
	agentNetworkNoProvidersText = "No Agent Networks policy gives you access. Ask your administrator."
	agentNetworkBlockedText     = "Your NetBird user is blocked or waiting for approval, " +
		"so Agent Networks is not available. Ask your administrator."
	// The two texts below are returned as errors, so they carry no final period.
	agentNetworkUnsupportedText = "the NetBird management server does not report Agent Networks usage; " +
		"ask your administrator to upgrade it"
	agentNetworkNotConnectedText = "NetBird is not connected. Run `netbird up` first"
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
	agentNetworkUsageCmd.Flags().BoolVar(&agentNetworkUsageJSON, "json", false, "print the response as JSON")
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
	return renderAgentNetworkUsage(cmd.OutOrStdout(), resp, time.Now(), agentNetworkUsageJSON)
}

// agentNetworkInfoError turns the daemon's "client is not running" refusal
// into the action the user has to take.
func agentNetworkInfoError(err error) error {
	if gstatus.Code(err) == codes.FailedPrecondition {
		return errors.New(agentNetworkNotConnectedText)
	}
	return daemonCallError("get Agent Networks info", err)
}

// renderAgentNetworkUsage prints resp. Reset countdowns are relative to now.
// JSON reports every state with exit code 0; text mode fails when management
// cannot answer.
func renderAgentNetworkUsage(w io.Writer, resp *proto.GetAgentNetworkInfoResponse, now time.Time, asJSON bool) error {
	if asJSON {
		return writeAgentNetworkJSON(w, resp)
	}
	if resp.GetState() == proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED {
		return errors.New(agentNetworkUnsupportedText)
	}

	switch resp.GetState() {
	case proto.GetAgentNetworkInfoResponse_OK:
		return writeAgentNetworkProviders(w, resp, now)
	case proto.GetAgentNetworkInfoResponse_NOT_ENABLED:
		fmt.Fprintln(w, agentNetworkNotEnabledText)
	case proto.GetAgentNetworkInfoResponse_USER_BLOCKED:
		fmt.Fprintln(w, agentNetworkBlockedText)
	default:
		return fmt.Errorf("unexpected Agent Networks state %s", resp.GetState())
	}
	return nil
}

// writeAgentNetworkJSON prints the daemon response as JSON.
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

func writeAgentNetworkProviders(w io.Writer, resp *proto.GetAgentNetworkInfoResponse, now time.Time) error {
	if len(resp.GetProviders()) == 0 {
		_, err := fmt.Fprintln(w, agentNetworkNoProvidersText)
		return err
	}

	fmt.Fprintln(w, "Agent Networks usage")
	for _, p := range resp.GetProviders() {
		fmt.Fprintf(w, "\n%s (%s)", p.GetName(), p.GetCatalogId())
		if p.GetExhausted() {
			fmt.Fprint(w, " - exhausted, requests are refused until a limit resets")
		}
		fmt.Fprintln(w)

		switch {
		case len(p.GetLimits()) > 0:
			if err := writeAgentNetworkLimits(w, p.GetLimits(), now); err != nil {
				return err
			}
		case p.GetUnlimited():
			fmt.Fprintln(w, "  Unlimited")
		default:
			fmt.Fprintln(w, "  No limits apply")
		}
	}
	return nil
}

func writeAgentNetworkLimits(w io.Writer, limits []*proto.AgentNetworkLimit, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  USED / CAP\tREMAINING\tRESETS")
	for _, l := range limits {
		remaining := l.GetCap() - l.GetUsed()
		if remaining < 0 {
			remaining = 0
		}
		fmt.Fprintf(tw, "  %s / %s\t%s\t%s\n",
			formatLimitAmount(l.GetUnit(), l.GetUsed(), false),
			formatLimitAmount(l.GetUnit(), l.GetCap(), true),
			formatLimitAmount(l.GetUnit(), remaining, true),
			formatLimitReset(l, now),
		)
	}
	return tw.Flush()
}

func formatLimitAmount(unit proto.AgentNetworkLimit_Unit, v float64, withUnit bool) string {
	var s, suffix string
	switch unit {
	case proto.AgentNetworkLimit_USD:
		return fmt.Sprintf("$%.2f", v)
	case proto.AgentNetworkLimit_TOKENS:
		s, suffix = groupThousands(int64(v)), " tokens"
	default:
		// A unit newer than this client: show the number, not a guessed unit.
		s, suffix = strconv.FormatFloat(v, 'f', -1, 64), " (unknown unit)"
	}
	if withUnit {
		s += suffix
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
	stamp := at.Local().Format("2006-01-02 15:04 MST")
	// A reset already past means the client clock is ahead of management's.
	if !at.After(now) {
		return fmt.Sprintf("now (%s)", stamp)
	}
	return fmt.Sprintf("in %s (%s)", formatUntil(at.Sub(now)), stamp)
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
