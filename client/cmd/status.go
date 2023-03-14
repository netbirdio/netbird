package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

type peerStateDetailOutput struct {
	FQDN             string           `json:"fqdn" yaml:"fqdn"`
	IP               string           `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey           string           `json:"publicKey" yaml:"publicKey"`
	Status           string           `json:"status" yaml:"status"`
	LastStatusUpdate time.Time        `json:"lastStatusUpdate" yaml:"lastStatusUpdate"`
	ConnType         string           `json:"connectionType" yaml:"connectionType"`
	Direct           bool             `json:"direct" yaml:"direct"`
	IceCandidateType iceCandidateType `json:"iceCandidateType" yaml:"iceCandidateType"`
}

type peersStateOutput struct {
	Total     int                     `json:"total" yaml:"total"`
	Connected int                     `json:"connected" yaml:"connected"`
	Details   []peerStateDetailOutput `json:"details" yaml:"details"`
}

type signalStateOutput struct {
	URL       string `json:"url" yaml:"url"`
	Connected bool   `json:"connected" yaml:"connected"`
}

type managementStateOutput struct {
	URL       string `json:"url" yaml:"url"`
	Connected bool   `json:"connected" yaml:"connected"`
}

type iceCandidateType struct {
	Local  string `json:"local" yaml:"local"`
	Remote string `json:"remote" yaml:"remote"`
}

type statusOutputOverview struct {
	Peers           peersStateOutput      `json:"peers" yaml:"peers"`
	CliVersion      string                `json:"cliVersion" yaml:"cliVersion"`
	DaemonVersion   string                `json:"daemonVersion" yaml:"daemonVersion"`
	ManagementState managementStateOutput `json:"management" yaml:"management"`
	SignalState     signalStateOutput     `json:"signal" yaml:"signal"`
	IP              string                `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey          string                `json:"publicKey" yaml:"publicKey"`
	KernelInterface bool                  `json:"usesKernelInterface" yaml:"usesKernelInterface"`
	FQDN            string                `json:"fqdn" yaml:"fqdn"`
}

var (
	detailFlag   bool
	ipv4Flag     bool
	jsonFlag     bool
	yamlFlag     bool
	ipsFilter    []string
	statusFilter string
	ipsFilterMap map[string]struct{}
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "status of the Netbird Service",
	RunE:  statusFunc,
}

func init() {
	ipsFilterMap = make(map[string]struct{})
	statusCmd.PersistentFlags().BoolVarP(&detailFlag, "detail", "d", false, "display detailed status information in human-readable format")
	statusCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "display detailed status information in json format")
	statusCmd.PersistentFlags().BoolVar(&yamlFlag, "yaml", false, "display detailed status information in yaml format")
	statusCmd.PersistentFlags().BoolVar(&ipv4Flag, "ipv4", false, "display only NetBird IPv4 of this peer, e.g., --ipv4 will output 100.64.0.33")
	statusCmd.MarkFlagsMutuallyExclusive("detail", "json", "yaml", "ipv4")
	statusCmd.PersistentFlags().StringSliceVar(&ipsFilter, "filter-by-ips", []string{}, "filters the detailed output by a list of one or more IPs, e.g., --filter-by-ips 100.64.0.100,100.64.0.200")
	statusCmd.PersistentFlags().StringVar(&statusFilter, "filter-by-status", "", "filters the detailed output by connection status(connected|disconnected), e.g., --filter-by-status connected")
}

func statusFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)

	cmd.SetOut(cmd.OutOrStdout())

	err := parseFilters()
	if err != nil {
		return err
	}

	err = util.InitLog(logLevel, "console")
	if err != nil {
		return fmt.Errorf("failed initializing log %v", err)
	}

	ctx := internal.CtxInitState(context.Background())

	resp, _ := getStatus(ctx, cmd)
	if err != nil {
		return nil
	}

	if resp.GetStatus() == string(internal.StatusNeedsLogin) || resp.GetStatus() == string(internal.StatusLoginFailed) {
		cmd.Printf("Daemon status: %s\n\n"+
			"Run UP command to log in with SSO (interactive login):\n\n"+
			" netbird up \n\n"+
			"If you are running a self-hosted version and no SSO provider has been configured in your Management Server,\n"+
			"you can use a setup-key:\n\n netbird up --management-url <YOUR_MANAGEMENT_URL> --setup-key <YOUR_SETUP_KEY>\n\n"+
			"More info: https://www.netbird.io/docs/overview/setup-keys\n\n",
			resp.GetStatus(),
		)
		return nil
	}

	if ipv4Flag {
		cmd.Print(parseInterfaceIP(resp.GetFullStatus().GetLocalPeerState().GetIP()))
		return nil
	}

	outputInformationHolder := convertToStatusOutputOverview(resp)

	statusOutputString := ""
	switch {
	case detailFlag:
		statusOutputString = parseToFullDetailSummary(outputInformationHolder)
	case jsonFlag:
		statusOutputString, err = parseToJSON(outputInformationHolder)
	case yamlFlag:
		statusOutputString, err = parseToYAML(outputInformationHolder)
	default:
		statusOutputString = parseGeneralSummary(outputInformationHolder, false)
	}

	if err != nil {
		return err
	}

	cmd.Print(statusOutputString)

	return nil
}

func getStatus(ctx context.Context, cmd *cobra.Command) (*proto.StatusResponse, error) {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer conn.Close()

	resp, err := proto.NewDaemonServiceClient(conn).Status(cmd.Context(), &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		return nil, fmt.Errorf("status failed: %v", status.Convert(err).Message())
	}

	return resp, nil
}

func parseFilters() error {
	switch strings.ToLower(statusFilter) {
	case "", "disconnected", "connected":
	default:
		return fmt.Errorf("wrong status filter, should be one of connected|disconnected, got: %s", statusFilter)
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
	return nil
}

func convertToStatusOutputOverview(resp *proto.StatusResponse) statusOutputOverview {
	pbFullStatus := resp.GetFullStatus()

	managementState := pbFullStatus.GetManagementState()
	managementOverview := managementStateOutput{
		URL:       managementState.GetURL(),
		Connected: managementState.GetConnected(),
	}

	signalState := pbFullStatus.GetSignalState()
	signalOverview := signalStateOutput{
		URL:       signalState.GetURL(),
		Connected: signalState.GetConnected(),
	}

	peersOverview := mapPeers(resp.GetFullStatus().GetPeers())

	overview := statusOutputOverview{
		Peers:           peersOverview,
		CliVersion:      version.NetbirdVersion(),
		DaemonVersion:   resp.GetDaemonVersion(),
		ManagementState: managementOverview,
		SignalState:     signalOverview,
		IP:              pbFullStatus.GetLocalPeerState().GetIP(),
		PubKey:          pbFullStatus.GetLocalPeerState().GetPubKey(),
		KernelInterface: pbFullStatus.GetLocalPeerState().GetKernelInterface(),
		FQDN:            pbFullStatus.GetLocalPeerState().GetFqdn(),
	}

	return overview
}

func mapPeers(peers []*proto.PeerState) peersStateOutput {
	var peersStateDetail []peerStateDetailOutput
	localICE := ""
	remoteICE := ""
	connType := ""
	peersConnected := 0
	for _, pbPeerState := range peers {
		isPeerConnected := pbPeerState.ConnStatus == peer.StatusConnected.String()
		if skipDetailByFilters(pbPeerState, isPeerConnected) {
			continue
		}
		if isPeerConnected {
			peersConnected = peersConnected + 1

			localICE = pbPeerState.GetLocalIceCandidateType()
			remoteICE = pbPeerState.GetRemoteIceCandidateType()
			connType = "P2P"
			if pbPeerState.Relayed {
				connType = "Relayed"
			}
		}

		timeLocal := pbPeerState.GetConnStatusUpdate().AsTime().Local()
		peerState := peerStateDetailOutput{
			IP:               pbPeerState.GetIP(),
			PubKey:           pbPeerState.GetPubKey(),
			Status:           pbPeerState.GetConnStatus(),
			LastStatusUpdate: timeLocal.UTC(),
			ConnType:         connType,
			Direct:           pbPeerState.GetDirect(),
			IceCandidateType: iceCandidateType{
				Local:  localICE,
				Remote: remoteICE,
			},
			FQDN: pbPeerState.GetFqdn(),
		}

		peersStateDetail = append(peersStateDetail, peerState)
	}

	sortPeersByIP(peersStateDetail)

	peersOverview := peersStateOutput{
		Total:     len(peersStateDetail),
		Connected: peersConnected,
		Details:   peersStateDetail,
	}
	return peersOverview
}

func sortPeersByIP(peersStateDetail []peerStateDetailOutput) {
	if len(peersStateDetail) > 0 {
		sort.SliceStable(peersStateDetail, func(i, j int) bool {
			iAddr, _ := netip.ParseAddr(peersStateDetail[i].IP)
			jAddr, _ := netip.ParseAddr(peersStateDetail[j].IP)
			return iAddr.Compare(jAddr) == -1
		})
	}
}

func parseInterfaceIP(interfaceIP string) string {
	ip, _, err := net.ParseCIDR(interfaceIP)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s\n", ip)
}

func parseToJSON(overview statusOutputOverview) (string, error) {
	jsonBytes, err := json.Marshal(overview)
	if err != nil {
		return "", fmt.Errorf("json marshal failed")
	}
	return string(jsonBytes), err
}

func parseToYAML(overview statusOutputOverview) (string, error) {
	yamlBytes, err := yaml.Marshal(overview)
	if err != nil {
		return "", fmt.Errorf("yaml marshal failed")
	}
	return string(yamlBytes), nil
}

func parseGeneralSummary(overview statusOutputOverview, showURL bool) string {

	managementConnString := "Disconnected"
	if overview.ManagementState.Connected {
		managementConnString = "Connected"
		if showURL {
			managementConnString = fmt.Sprintf("%s to %s", managementConnString, overview.ManagementState.URL)
		}
	}

	signalConnString := "Disconnected"
	if overview.SignalState.Connected {
		signalConnString = "Connected"
		if showURL {
			signalConnString = fmt.Sprintf("%s to %s", signalConnString, overview.SignalState.URL)
		}
	}

	interfaceTypeString := "Userspace"
	interfaceIP := overview.IP
	if overview.KernelInterface {
		interfaceTypeString = "Kernel"
	} else if overview.IP == "" {
		interfaceTypeString = "N/A"
		interfaceIP = "N/A"
	}

	peersCountString := fmt.Sprintf("%d/%d Connected", overview.Peers.Connected, overview.Peers.Total)

	summary := fmt.Sprintf(
		"Daemon version: %s\n"+
			"CLI version: %s\n"+
			"Management: %s\n"+
			"Signal: %s\n"+
			"FQDN: %s\n"+
			"NetBird IP: %s\n"+
			"Interface type: %s\n"+
			"Peers count: %s\n",
		overview.DaemonVersion,
		version.NetbirdVersion(),
		managementConnString,
		signalConnString,
		overview.FQDN,
		interfaceIP,
		interfaceTypeString,
		peersCountString,
	)
	return summary
}

func parseToFullDetailSummary(overview statusOutputOverview) string {
	parsedPeersString := parsePeers(overview.Peers)
	summary := parseGeneralSummary(overview, true)

	return fmt.Sprintf(
		"Peers detail:"+
			"%s\n"+
			"%s",
		parsedPeersString,
		summary,
	)
}

func parsePeers(peers peersStateOutput) string {
	var (
		peersString = ""
	)

	for _, peerState := range peers.Details {

		localICE := "-"
		if peerState.IceCandidateType.Local != "" {
			localICE = peerState.IceCandidateType.Local
		}

		remoteICE := "-"
		if peerState.IceCandidateType.Remote != "" {
			remoteICE = peerState.IceCandidateType.Remote
		}

		peerString := fmt.Sprintf(
			"\n %s:\n"+
				"  NetBird IP: %s\n"+
				"  Public key: %s\n"+
				"  Status: %s\n"+
				"  -- detail --\n"+
				"  Connection type: %s\n"+
				"  Direct: %t\n"+
				"  ICE candidate (Local/Remote): %s/%s\n"+
				"  Last connection update: %s\n",
			peerState.FQDN,
			peerState.IP,
			peerState.PubKey,
			peerState.Status,
			peerState.ConnType,
			peerState.Direct,
			localICE,
			remoteICE,
			peerState.LastStatusUpdate.Format("2006-01-02 15:04:05"),
		)

		peersString = peersString + peerString
	}
	return peersString
}

func skipDetailByFilters(peerState *proto.PeerState, isConnected bool) bool {
	statusEval := false
	ipEval := false

	if statusFilter != "" {
		lowerStatusFilter := strings.ToLower(statusFilter)
		if lowerStatusFilter == "disconnected" && isConnected {
			statusEval = true
		} else if lowerStatusFilter == "connected" && !isConnected {
			statusEval = true
		}
	}

	if len(ipsFilter) > 0 {
		_, ok := ipsFilterMap[peerState.IP]
		if !ok {
			ipEval = true
		}
	}
	return statusEval || ipEval
}
