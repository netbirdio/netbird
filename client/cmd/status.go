package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	nbstatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

// statusOutput is a format accepted by status --output.
type statusOutput string

const (
	outputSummary statusOutput = ""
	outputDetail  statusOutput = "detail"
	outputTable   statusOutput = "table"
	outputJSON    statusOutput = "json"
	outputYAML    statusOutput = "yaml"
	outputIPv4    statusOutput = "ipv4"
	outputIPv6    statusOutput = "ipv6"
)

var statusOutputs = []statusOutput{outputDetail, outputTable, outputJSON, outputYAML, outputIPv4, outputIPv6}

const outputFlagName = "output"

var (
	outputFlag           string
	detailFlag           bool
	tableFlag            bool
	ipv4Flag             bool
	ipv6Flag             bool
	jsonFlag             bool
	yamlFlag             bool
	ipsFilter            []string
	prefixNamesFilter    []string
	statusFilter         string
	ipsFilterMap         map[string]struct{}
	prefixNamesFilterMap map[string]struct{}
	connectionTypeFilter string
	checkFlag            string
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display NetBird client status",
	Long:  "Display the current status of the NetBird client, including connection status, peer information, and network details.",
	RunE:  statusFunc,
}

func init() {
	ipsFilterMap = make(map[string]struct{})
	prefixNamesFilterMap = make(map[string]struct{})
	statusCmd.PersistentFlags().StringVarP(&outputFlag, outputFlagName, "o", "", "output format: detail (human-readable details), table (peers in a table), json, yaml, ipv4 (only this peer's NetBird IPv4) or ipv6 (only this peer's NetBird IPv6). Prints a short summary if not set, or detail if a --filter-by-* flag is set. The --filter-by-* flags apply to all formats except ipv4 and ipv6")
	_ = statusCmd.RegisterFlagCompletionFunc(outputFlagName, cobra.FixedCompletions(statusOutputNames(), cobra.ShellCompDirectiveNoFileComp))
	addLegacyOutputFlag(&detailFlag, outputDetail, "d")
	addLegacyOutputFlag(&tableFlag, outputTable, "t")
	addLegacyOutputFlag(&jsonFlag, outputJSON, "j")
	addLegacyOutputFlag(&yamlFlag, outputYAML, "y")
	addLegacyOutputFlag(&ipv4Flag, outputIPv4, "4")
	addLegacyOutputFlag(&ipv6Flag, outputIPv6, "6")
	statusCmd.MarkFlagsMutuallyExclusive(outputFlagName, "detail", "table", "json", "yaml", "ipv4", "ipv6")
	statusCmd.PersistentFlags().StringSliceVarP(&ipsFilter, "filter-by-ips", "I", []string{}, "filters the peers in the detail, table, json and yaml output by a list of one or more IPs (v4 or v6), e.g., --filter-by-ips 100.64.0.100,fd00::1")
	statusCmd.PersistentFlags().StringSliceVarP(&prefixNamesFilter, "filter-by-names", "N", []string{}, "filters the peers in the detail, table, json and yaml output by a list of one or more peer FQDN or hostnames, e.g., --filter-by-names peer-a,peer-b.netbird.cloud")
	statusCmd.PersistentFlags().StringVarP(&statusFilter, "filter-by-status", "S", "", "filters the peers in the detail, table, json and yaml output by connection status (idle|connecting|connected), e.g., --filter-by-status connected")
	statusCmd.PersistentFlags().StringVarP(&connectionTypeFilter, "filter-by-connection-type", "T", "", "filters the peers in the detail, table, json and yaml output by connection type (P2P|Relayed), e.g., --filter-by-connection-type P2P")
	statusCmd.Flags().AddFlagSet(anonymizeFlags)
	statusCmd.PersistentFlags().StringVarP(&checkFlag, "check", "C", "", "run a health check and exit with code 0 on success, 1 on failure (live|ready|startup)")
}

func statusFunc(cmd *cobra.Command, args []string) error {
	cmd.SetOut(cmd.OutOrStdout())

	if checkFlag != "" {
		return runHealthCheck(cmd)
	}

	output, err := resolveStatusOutput()
	if err != nil {
		return err
	}

	if err := parseFilters(); err != nil {
		return err
	}

	err = util.InitLog(logLevel, util.LogConsole)
	if err != nil {
		return fmt.Errorf("failed initializing log %v", err)
	}

	ctx := internal.CtxInitState(cmd.Context())

	resp, err := getStatus(ctx, true, false)
	if err != nil {
		return err
	}

	status := resp.GetStatus()

	needsAuth := status == string(internal.StatusNeedsLogin) || status == string(internal.StatusLoginFailed) ||
		status == string(internal.StatusSessionExpired)

	if needsAuth && output != outputJSON && output != outputYAML {
		cmd.Printf("Daemon status: %s\n\n"+
			"Run UP command to log in with SSO (interactive login):\n\n"+
			" netbird up \n\n"+
			"If you are running a self-hosted version and no SSO provider has been configured in your Management Server,\n"+
			"you can use a setup-key:\n\n netbird up --management-url <YOUR_MANAGEMENT_URL> --setup-key <YOUR_SETUP_KEY>\n\n"+
			"More info: https://docs.netbird.io/how-to/register-machines-using-setup-keys\n\n",
			resp.GetStatus(),
		)
		return nil
	}

	if resp.GetFullStatus() == nil {
		overview := nbstatus.OutputOverview{
			DaemonVersion: resp.GetDaemonVersion(),
			CliVersion:    version.NetbirdVersion(),
			DaemonStatus:  nbstatus.DaemonStatus(status),
		}
		var outputString string
		var err error
		switch output {
		case outputJSON:
			outputString, err = overview.JSON()
		case outputYAML:
			outputString, err = overview.YAML()
		default:
			outputString = fmt.Sprintf("Daemon status: %s\n"+
				"Daemon version: %s\nCLI version: %s\n\n"+
				"Detailed status is unavailable: the connection belongs to another user.\n",
				status, resp.GetDaemonVersion(), version.NetbirdVersion())
		}

		if err != nil {
			return err
		}

		cmd.Print(outputString)
		return nil
	}

	if output == outputIPv4 {
		cmd.Print(parseInterfaceIP(resp.GetFullStatus().GetLocalPeerState().GetIP()))
		return nil
	}

	if output == outputIPv6 {
		ipv6 := resp.GetFullStatus().GetLocalPeerState().GetIpv6()
		if ipv6 != "" {
			cmd.Print(parseInterfaceIP(ipv6))
		}
		return nil
	}

	// Resolve the active profile's display name via the daemon, which runs
	// as root and can read the per-user profile files. The local profile
	// manager only knows the active profile ID, not its display name.
	profName := getActiveProfileName(ctx)

	var sessionExpiresAt time.Time
	if ts := resp.GetSessionExpiresAt(); ts.IsValid() {
		sessionExpiresAt = ts.AsTime().UTC()
	}

	anonymizeEnabled, anonymizeLevel, err := effectiveAnonymize()
	if err != nil {
		return err
	}

	var outputInformationHolder = nbstatus.ConvertToStatusOutputOverview(resp.GetFullStatus(), nbstatus.ConvertOptions{
		Anonymize:            anonymizeEnabled,
		AnonymizeLevel:       anonymizeLevel,
		DaemonVersion:        resp.GetDaemonVersion(),
		DaemonStatus:         nbstatus.ParseDaemonStatus(status),
		StatusFilter:         statusFilter,
		PrefixNamesFilter:    prefixNamesFilter,
		PrefixNamesFilterMap: prefixNamesFilterMap,
		IPsFilter:            ipsFilterMap,
		ConnectionTypeFilter: connectionTypeFilter,
		ProfileName:          profName,
		SessionExpiresAt:     sessionExpiresAt,
	})
	var statusOutputString string
	switch output {
	case outputDetail:
		statusOutputString = outputInformationHolder.FullDetailSummary()
	case outputTable:
		statusOutputString = outputInformationHolder.PeersTable()
	case outputJSON:
		statusOutputString, err = outputInformationHolder.JSON()
	case outputYAML:
		statusOutputString, err = outputInformationHolder.YAML()
	default:
		statusOutputString = outputInformationHolder.GeneralSummary(false, false, false, false)
	}

	if err != nil {
		return err
	}

	cmd.Print(statusOutputString)

	return nil
}

func getStatus(ctx context.Context, fullPeerStatus bool, shouldRunProbes bool) (*proto.StatusResponse, error) {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return nil, daemonConnectError(err)
	}
	defer conn.Close()

	resp, err := proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{GetFullPeerStatus: fullPeerStatus, ShouldRunProbes: shouldRunProbes})
	if err != nil {
		return nil, fmt.Errorf("status failed: %v", status.Convert(err).Message())
	}

	return resp, nil
}

// getActiveProfileName asks the daemon for the active profile's display
// name. The daemon runs as root and can read the per-user profile files to
// resolve the ID to its human-readable name. Returns an empty string on any
// error so status output degrades gracefully.
func getActiveProfileName(ctx context.Context) string {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	resp, err := proto.NewDaemonServiceClient(conn).GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		return ""
	}

	return resp.GetProfileName()
}

func parseFilters() error {
	switch strings.ToLower(statusFilter) {
	case "", "idle", "connecting", "connected":
	default:
		return fmt.Errorf("wrong status filter, should be one of connected|connecting|idle, got: %s", statusFilter)
	}

	if len(ipsFilter) > 0 {
		for _, addr := range ipsFilter {
			_, err := netip.ParseAddr(addr)
			if err != nil {
				return fmt.Errorf("got an invalid IP address in the filter: address %s, error %s", addr, err)
			}
			ipsFilterMap[addr] = struct{}{}
		}
	}

	for _, name := range prefixNamesFilter {
		prefixNamesFilterMap[strings.ToLower(name)] = struct{}{}
	}

	switch strings.ToLower(connectionTypeFilter) {
	case "", "p2p", "relayed":
	default:
		return fmt.Errorf("wrong connection-type filter, should be one of P2P|Relayed, got: %s", connectionTypeFilter)
	}

	return nil
}

// addLegacyOutputFlag registers a hidden boolean flag that selects output.
func addLegacyOutputFlag(p *bool, output statusOutput, shorthand string) {
	name := string(output)
	statusCmd.PersistentFlags().BoolVarP(p, name, shorthand, false, fmt.Sprintf("same as --%s %s", outputFlagName, name))
	_ = statusCmd.PersistentFlags().MarkHidden(name)
}

// resolveStatusOutput returns the format chosen by --output or a hidden
// format flag. Without either, a filter selects detail.
func resolveStatusOutput() (statusOutput, error) {
	output := statusOutput(strings.ToLower(outputFlag))
	if output == outputSummary {
		output = legacyStatusOutput()
	}

	if output != outputSummary && !slices.Contains(statusOutputs, output) {
		return "", fmt.Errorf("unknown output %q, must be one of: %s", outputFlag, strings.Join(statusOutputNames(), ", "))
	}

	if output == outputSummary && hasStatusFilters() {
		return outputDetail, nil
	}

	return output, nil
}

func legacyStatusOutput() statusOutput {
	switch {
	case detailFlag:
		return outputDetail
	case tableFlag:
		return outputTable
	case jsonFlag:
		return outputJSON
	case yamlFlag:
		return outputYAML
	case ipv4Flag:
		return outputIPv4
	case ipv6Flag:
		return outputIPv6
	default:
		return outputSummary
	}
}

func hasStatusFilters() bool {
	return statusFilter != "" || len(ipsFilter) > 0 || len(prefixNamesFilter) > 0 || connectionTypeFilter != ""
}

func statusOutputNames() []string {
	names := make([]string, 0, len(statusOutputs))
	for _, output := range statusOutputs {
		names = append(names, string(output))
	}
	return names
}

func runHealthCheck(cmd *cobra.Command) error {
	check := strings.ToLower(checkFlag)
	switch check {
	case "live", "ready", "startup":
	default:
		return fmt.Errorf("unknown check %q, must be one of: live, ready, startup", checkFlag)
	}

	if err := util.InitLog(logLevel, util.LogConsole); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := internal.CtxInitState(cmd.Context())

	isStartup := check == "startup"
	resp, err := getStatus(ctx, isStartup, false)
	if err != nil {
		return err
	}

	switch check {
	case "live":
		return nil
	case "ready":
		return checkReadiness(resp)
	case "startup":
		return checkStartup(resp)
	default:
		return nil
	}
}

func checkReadiness(resp *proto.StatusResponse) error {
	daemonStatus := internal.StatusType(resp.GetStatus())
	switch daemonStatus {
	case internal.StatusIdle, internal.StatusConnecting, internal.StatusConnected:
		return nil
	case internal.StatusNeedsLogin, internal.StatusLoginFailed, internal.StatusSessionExpired:
		return fmt.Errorf("readiness check: daemon status is %s", daemonStatus)
	default:
		return fmt.Errorf("readiness check: unexpected daemon status %q", daemonStatus)
	}
}

func checkStartup(resp *proto.StatusResponse) error {
	fullStatus := resp.GetFullStatus()
	if fullStatus == nil {
		return fmt.Errorf("startup check: no full status available")
	}

	if !fullStatus.GetManagementState().GetConnected() {
		return fmt.Errorf("startup check: management not connected")
	}

	if !fullStatus.GetSignalState().GetConnected() {
		return fmt.Errorf("startup check: signal not connected")
	}

	var relayCount, relaysConnected int
	for _, r := range fullStatus.GetRelays() {
		uri := r.GetURI()
		if !strings.HasPrefix(uri, "rel://") && !strings.HasPrefix(uri, "rels://") {
			continue
		}
		relayCount++
		if r.GetAvailable() {
			relaysConnected++
		}
	}

	if relayCount > 0 && relaysConnected == 0 {
		return fmt.Errorf("startup check: no relay servers available (0/%d connected)", relayCount)
	}

	return nil
}

func parseInterfaceIP(interfaceIP string) string {
	ip, _, err := net.ParseCIDR(interfaceIP)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s\n", ip)
}
