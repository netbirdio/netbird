package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	nbstatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/util"
)

var (
	detailFlag           bool
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
	statusCmd.PersistentFlags().BoolVarP(&detailFlag, "detail", "d", false, "display detailed status information in human-readable format")
	statusCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "display detailed status information in json format")
	statusCmd.PersistentFlags().BoolVarP(&yamlFlag, "yaml", "y", false, "display detailed status information in yaml format")
	statusCmd.PersistentFlags().BoolVarP(&ipv4Flag, "ipv4", "4", false, "display only NetBird IPv4 of this peer, e.g., --ipv4 will output 100.64.0.33")
	statusCmd.PersistentFlags().BoolVarP(&ipv6Flag, "ipv6", "6", false, "display only NetBird IPv6 of this peer")
	statusCmd.MarkFlagsMutuallyExclusive("detail", "json", "yaml", "ipv4", "ipv6")
	statusCmd.PersistentFlags().StringSliceVarP(&ipsFilter, "filter-by-ips", "I", []string{}, "filters the detailed output by a list of one or more IPs (v4 or v6), e.g., --filter-by-ips 100.64.0.100,fd00::1")
	statusCmd.PersistentFlags().StringSliceVarP(&prefixNamesFilter, "filter-by-names", "N", []string{}, "filters the detailed output by a list of one or more peer FQDN or hostnames, e.g., --filter-by-names peer-a,peer-b.netbird.cloud")
	statusCmd.PersistentFlags().StringVarP(&statusFilter, "filter-by-status", "S", "", "filters the detailed output by connection status(idle|connecting|connected), e.g., --filter-by-status connected")
	statusCmd.PersistentFlags().StringVarP(&connectionTypeFilter, "filter-by-connection-type", "T", "", "filters the detailed output by connection type (P2P|Relayed), e.g., --filter-by-connection-type P2P")
	statusCmd.PersistentFlags().StringVarP(&checkFlag, "check", "C", "", "run a health check and exit with code 0 on success, 1 on failure (live|ready|startup)")
}

func statusFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)

	cmd.SetOut(cmd.OutOrStdout())

	if checkFlag != "" {
		return runHealthCheck(cmd)
	}

	err := parseFilters()
	if err != nil {
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

	if needsAuth && !jsonFlag && !yamlFlag {
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

	if ipv4Flag {
		cmd.Print(parseInterfaceIP(resp.GetFullStatus().GetLocalPeerState().GetIP()))
		return nil
	}

	if ipv6Flag {
		ipv6 := resp.GetFullStatus().GetLocalPeerState().GetIpv6()
		if ipv6 != "" {
			cmd.Print(parseInterfaceIP(ipv6))
		}
		return nil
	}

	pm := profilemanager.NewProfileManager()
	var profName string
	if activeProf, err := pm.GetActiveProfile(); err == nil {
		profName = activeProf.Name
	}

	var outputInformationHolder = nbstatus.ConvertToStatusOutputOverview(resp.GetFullStatus(), nbstatus.ConvertOptions{
		Anonymize:            anonymizeFlag,
		DaemonVersion:        resp.GetDaemonVersion(),
		DaemonStatus:         nbstatus.ParseDaemonStatus(status),
		StatusFilter:         statusFilter,
		PrefixNamesFilter:    prefixNamesFilter,
		PrefixNamesFilterMap: prefixNamesFilterMap,
		IPsFilter:            ipsFilterMap,
		ConnectionTypeFilter: connectionTypeFilter,
		ProfileName:          profName,
	})
	var statusOutputString string
	switch {
	case detailFlag:
		statusOutputString = outputInformationHolder.FullDetailSummary()
	case jsonFlag:
		statusOutputString, err = outputInformationHolder.JSON()
	case yamlFlag:
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
		//nolint
		return nil, fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer conn.Close()

	resp, err := proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{GetFullPeerStatus: fullPeerStatus, ShouldRunProbes: shouldRunProbes})
	if err != nil {
		return nil, fmt.Errorf("status failed: %v", status.Convert(err).Message())
	}

	return resp, nil
}

func parseFilters() error {
	switch strings.ToLower(statusFilter) {
	case "", "idle", "connecting", "connected":
		if strings.ToLower(statusFilter) != "" {
			enableDetailFlagWhenFilterFlag()
		}
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
			enableDetailFlagWhenFilterFlag()
		}
	}

	if len(prefixNamesFilter) > 0 {
		for _, name := range prefixNamesFilter {
			prefixNamesFilterMap[strings.ToLower(name)] = struct{}{}
		}
		enableDetailFlagWhenFilterFlag()
	}

	switch strings.ToLower(connectionTypeFilter) {
	case "", "p2p", "relayed":
		if strings.ToLower(connectionTypeFilter) != "" {
			enableDetailFlagWhenFilterFlag()
		}
	default:
		return fmt.Errorf("wrong connection-type filter, should be one of P2P|Relayed, got: %s", connectionTypeFilter)
	}

	return nil
}

func enableDetailFlagWhenFilterFlag() {
	if !detailFlag && !jsonFlag && !yamlFlag {
		detailFlag = true
	}
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
