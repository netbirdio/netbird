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
	jsonFlag             bool
	yamlFlag             bool
	ipsFilter            []string
	prefixNamesFilter    []string
	statusFilter         string
	ipsFilterMap         map[string]struct{}
	prefixNamesFilterMap map[string]struct{}
	connectionTypeFilter string
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
	statusCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "display detailed status information in json format")
	statusCmd.PersistentFlags().BoolVar(&yamlFlag, "yaml", false, "display detailed status information in yaml format")
	statusCmd.PersistentFlags().BoolVar(&ipv4Flag, "ipv4", false, "display only NetBird IPv4 of this peer, e.g., --ipv4 will output 100.64.0.33")
	statusCmd.MarkFlagsMutuallyExclusive("detail", "json", "yaml", "ipv4")
	statusCmd.PersistentFlags().StringSliceVar(&ipsFilter, "filter-by-ips", []string{}, "filters the detailed output by a list of one or more IPs, e.g., --filter-by-ips 100.64.0.100,100.64.0.200")
	statusCmd.PersistentFlags().StringSliceVar(&prefixNamesFilter, "filter-by-names", []string{}, "filters the detailed output by a list of one or more peer FQDN or hostnames, e.g., --filter-by-names peer-a,peer-b.netbird.cloud")
	statusCmd.PersistentFlags().StringVar(&statusFilter, "filter-by-status", "", "filters the detailed output by connection status(idle|connecting|connected), e.g., --filter-by-status connected")
	statusCmd.PersistentFlags().StringVar(&connectionTypeFilter, "filter-by-connection-type", "", "filters the detailed output by connection type (P2P|Relayed), e.g., --filter-by-connection-type P2P")
}

func statusFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)

	cmd.SetOut(cmd.OutOrStdout())

	err := parseFilters()
	if err != nil {
		return err
	}

	err = util.InitLog(logLevel, util.LogConsole)
	if err != nil {
		return fmt.Errorf("failed initializing log %v", err)
	}

	ctx := internal.CtxInitState(cmd.Context())

	resp, err := getStatus(ctx, false)
	if err != nil {
		return err
	}

	status := resp.GetStatus()

	if status == string(internal.StatusNeedsLogin) || status == string(internal.StatusLoginFailed) ||
		status == string(internal.StatusSessionExpired) {
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

	pm := profilemanager.NewProfileManager()
	var profName string
	if activeProf, err := pm.GetActiveProfile(); err == nil {
		profName = activeProf.Name
	}

	var outputInformationHolder = nbstatus.ConvertToStatusOutputOverview(resp.GetFullStatus(), anonymizeFlag, resp.GetDaemonVersion(), statusFilter, prefixNamesFilter, prefixNamesFilterMap, ipsFilterMap, connectionTypeFilter, profName)
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

func getStatus(ctx context.Context, shouldRunProbes bool) (*proto.StatusResponse, error) {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		//nolint
		return nil, fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer conn.Close()

	resp, err := proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true, ShouldRunProbes: shouldRunProbes})
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

func parseInterfaceIP(interfaceIP string) string {
	ip, _, err := net.ParseCIDR(interfaceIP)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s\n", ip)
}
