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
	FQDN                   string           `json:"fqdn" yaml:"fqdn"`
	IP                     string           `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey                 string           `json:"publicKey" yaml:"publicKey"`
	Status                 string           `json:"status" yaml:"status"`
	LastStatusUpdate       time.Time        `json:"lastStatusUpdate" yaml:"lastStatusUpdate"`
	ConnType               string           `json:"connectionType" yaml:"connectionType"`
	Direct                 bool             `json:"direct" yaml:"direct"`
	IceCandidateType       iceCandidateType `json:"iceCandidateType" yaml:"iceCandidateType"`
	IceCandidateEndpoint   iceCandidateType `json:"iceCandidateEndpoint" yaml:"iceCandidateEndpoint"`
	LastWireguardHandshake time.Time        `json:"lastWireguardHandshake" yaml:"lastWireguardHandshake"`
	TransferReceived       int64            `json:"transferReceived" yaml:"transferReceived"`
	TransferSent           int64            `json:"transferSent" yaml:"transferSent"`
}

type peersStateOutput struct {
	Total     int                     `json:"total" yaml:"total"`
	Connected int                     `json:"connected" yaml:"connected"`
	Details   []peerStateDetailOutput `json:"details" yaml:"details"`
}

type signalStateOutput struct {
	URL       string `json:"url" yaml:"url"`
	Connected bool   `json:"connected" yaml:"connected"`
	Error     string `json:"error" yaml:"error"`
}

type managementStateOutput struct {
	URL       string `json:"url" yaml:"url"`
	Connected bool   `json:"connected" yaml:"connected"`
	Error     string `json:"error" yaml:"error"`
}

type relayStateOutputDetail struct {
	URI       string `json:"uri" yaml:"uri"`
	Available bool   `json:"available" yaml:"available"`
	Error     string `json:"error" yaml:"error"`
}

type relayStateOutput struct {
	Total     int                      `json:"total" yaml:"total"`
	Available int                      `json:"available" yaml:"available"`
	Details   []relayStateOutputDetail `json:"details" yaml:"details"`
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
	Relays          relayStateOutput      `json:"relays" yaml:"relays"`
	IP              string                `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey          string                `json:"publicKey" yaml:"publicKey"`
	KernelInterface bool                  `json:"usesKernelInterface" yaml:"usesKernelInterface"`
	FQDN            string                `json:"fqdn" yaml:"fqdn"`
}

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
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "status of the Netbird Service",
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

	resp, err := getStatus(ctx, cmd)
	if err != nil {
		return err
	}

	if resp.GetStatus() == string(internal.StatusNeedsLogin) || resp.GetStatus() == string(internal.StatusLoginFailed) {
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

	outputInformationHolder := convertToStatusOutputOverview(resp)

	var statusOutputString string
	switch {
	case detailFlag:
		statusOutputString = parseToFullDetailSummary(outputInformationHolder)
	case jsonFlag:
		statusOutputString, err = parseToJSON(outputInformationHolder)
	case yamlFlag:
		statusOutputString, err = parseToYAML(outputInformationHolder)
	default:
		statusOutputString = parseGeneralSummary(outputInformationHolder, false, false)
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
		if strings.ToLower(statusFilter) != "" {
			enableDetailFlagWhenFilterFlag()
		}
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
			enableDetailFlagWhenFilterFlag()
		}
	}

	if len(prefixNamesFilter) > 0 {
		for _, name := range prefixNamesFilter {
			prefixNamesFilterMap[strings.ToLower(name)] = struct{}{}
		}
		enableDetailFlagWhenFilterFlag()
	}

	return nil
}

func enableDetailFlagWhenFilterFlag() {
	if !detailFlag && !jsonFlag && !yamlFlag {
		detailFlag = true
	}
}

func convertToStatusOutputOverview(resp *proto.StatusResponse) statusOutputOverview {
	pbFullStatus := resp.GetFullStatus()

	managementState := pbFullStatus.GetManagementState()
	managementOverview := managementStateOutput{
		URL:       managementState.GetURL(),
		Connected: managementState.GetConnected(),
		Error:     managementState.Error,
	}

	signalState := pbFullStatus.GetSignalState()
	signalOverview := signalStateOutput{
		URL:       signalState.GetURL(),
		Connected: signalState.GetConnected(),
		Error:     signalState.Error,
	}

	relayOverview := mapRelays(pbFullStatus.GetRelays())
	peersOverview := mapPeers(resp.GetFullStatus().GetPeers())

	overview := statusOutputOverview{
		Peers:           peersOverview,
		CliVersion:      version.NetbirdVersion(),
		DaemonVersion:   resp.GetDaemonVersion(),
		ManagementState: managementOverview,
		SignalState:     signalOverview,
		Relays:          relayOverview,
		IP:              pbFullStatus.GetLocalPeerState().GetIP(),
		PubKey:          pbFullStatus.GetLocalPeerState().GetPubKey(),
		KernelInterface: pbFullStatus.GetLocalPeerState().GetKernelInterface(),
		FQDN:            pbFullStatus.GetLocalPeerState().GetFqdn(),
	}

	return overview
}

func mapRelays(relays []*proto.RelayState) relayStateOutput {
	var relayStateDetail []relayStateOutputDetail

	var relaysAvailable int
	for _, relay := range relays {
		available := relay.GetAvailable()
		relayStateDetail = append(relayStateDetail,
			relayStateOutputDetail{
				URI:       relay.URI,
				Available: available,
				Error:     relay.GetError(),
			},
		)

		if available {
			relaysAvailable++
		}
	}

	return relayStateOutput{
		Total:     len(relays),
		Available: relaysAvailable,
		Details:   relayStateDetail,
	}
}

func mapPeers(peers []*proto.PeerState) peersStateOutput {
	var peersStateDetail []peerStateDetailOutput
	localICE := ""
	remoteICE := ""
	localICEEndpoint := ""
	remoteICEEndpoint := ""
	connType := ""
	peersConnected := 0
	lastHandshake := time.Time{}
	transferReceived := int64(0)
	transferSent := int64(0)
	for _, pbPeerState := range peers {
		isPeerConnected := pbPeerState.ConnStatus == peer.StatusConnected.String()
		if skipDetailByFilters(pbPeerState, isPeerConnected) {
			continue
		}
		if isPeerConnected {
			peersConnected++

			localICE = pbPeerState.GetLocalIceCandidateType()
			remoteICE = pbPeerState.GetRemoteIceCandidateType()
			localICEEndpoint = pbPeerState.GetLocalIceCandidateEndpoint()
			remoteICEEndpoint = pbPeerState.GetRemoteIceCandidateEndpoint()
			connType = "P2P"
			if pbPeerState.Relayed {
				connType = "Relayed"
			}
			lastHandshake = pbPeerState.GetLastWireguardHandshake().AsTime().Local()
			transferReceived = pbPeerState.GetBytesRx()
			transferSent = pbPeerState.GetBytesTx()
		}

		timeLocal := pbPeerState.GetConnStatusUpdate().AsTime().Local()
		peerState := peerStateDetailOutput{
			IP:               pbPeerState.GetIP(),
			PubKey:           pbPeerState.GetPubKey(),
			Status:           pbPeerState.GetConnStatus(),
			LastStatusUpdate: timeLocal,
			ConnType:         connType,
			Direct:           pbPeerState.GetDirect(),
			IceCandidateType: iceCandidateType{
				Local:  localICE,
				Remote: remoteICE,
			},
			IceCandidateEndpoint: iceCandidateType{
				Local:  localICEEndpoint,
				Remote: remoteICEEndpoint,
			},
			FQDN:                   pbPeerState.GetFqdn(),
			LastWireguardHandshake: lastHandshake,
			TransferReceived:       transferReceived,
			TransferSent:           transferSent,
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

func parseGeneralSummary(overview statusOutputOverview, showURL bool, showRelays bool) string {

	var managementConnString string
	if overview.ManagementState.Connected {
		managementConnString = "Connected"
		if showURL {
			managementConnString = fmt.Sprintf("%s to %s", managementConnString, overview.ManagementState.URL)
		}
	} else {
		managementConnString = "Disconnected"
		if overview.ManagementState.Error != "" {
			managementConnString = fmt.Sprintf("%s, reason: %s", managementConnString, overview.ManagementState.Error)
		}
	}

	var signalConnString string
	if overview.SignalState.Connected {
		signalConnString = "Connected"
		if showURL {
			signalConnString = fmt.Sprintf("%s to %s", signalConnString, overview.SignalState.URL)
		}
	} else {
		signalConnString = "Disconnected"
		if overview.SignalState.Error != "" {
			signalConnString = fmt.Sprintf("%s, reason: %s", signalConnString, overview.SignalState.Error)
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

	var relayAvailableString string
	if showRelays {
		for _, relay := range overview.Relays.Details {
			available := "Available"
			reason := ""
			if !relay.Available {
				available = "Unavailable"
				reason = fmt.Sprintf(", reason: %s", relay.Error)
			}
			relayAvailableString += fmt.Sprintf("\n  [%s] is %s%s", relay.URI, available, reason)

		}
	} else {

		relayAvailableString = fmt.Sprintf("%d/%d Available", overview.Relays.Available, overview.Relays.Total)
	}

	peersCountString := fmt.Sprintf("%d/%d Connected", overview.Peers.Connected, overview.Peers.Total)

	summary := fmt.Sprintf(
		"Daemon version: %s\n"+
			"CLI version: %s\n"+
			"Management: %s\n"+
			"Signal: %s\n"+
			"Relays: %s\n"+
			"FQDN: %s\n"+
			"NetBird IP: %s\n"+
			"Interface type: %s\n"+
			"Peers count: %s\n",
		overview.DaemonVersion,
		version.NetbirdVersion(),
		managementConnString,
		signalConnString,
		relayAvailableString,
		overview.FQDN,
		interfaceIP,
		interfaceTypeString,
		peersCountString,
	)
	return summary
}

func parseToFullDetailSummary(overview statusOutputOverview) string {
	parsedPeersString := parsePeers(overview.Peers)
	summary := parseGeneralSummary(overview, true, true)

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

		localICEEndpoint := "-"
		if peerState.IceCandidateEndpoint.Local != "" {
			localICEEndpoint = peerState.IceCandidateEndpoint.Local
		}

		remoteICEEndpoint := "-"
		if peerState.IceCandidateEndpoint.Remote != "" {
			remoteICEEndpoint = peerState.IceCandidateEndpoint.Remote
		}
		lastStatusUpdate := "-"
		if !peerState.LastStatusUpdate.IsZero() {
			lastStatusUpdate = peerState.LastStatusUpdate.Format("2006-01-02 15:04:05")
		}

		lastWireguardHandshake := "-"
		if !peerState.LastWireguardHandshake.IsZero() && peerState.LastWireguardHandshake != time.Unix(0, 0) {
			lastWireguardHandshake = peerState.LastWireguardHandshake.Format("2006-01-02 15:04:05")
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
				"  ICE candidate endpoints (Local/Remote): %s/%s\n"+
				"  Last connection update: %s\n"+
				"  Last Wireguard handshake: %s\n"+
				"  Transfer status (received/sent) %s/%s\n",
			peerState.FQDN,
			peerState.IP,
			peerState.PubKey,
			peerState.Status,
			peerState.ConnType,
			peerState.Direct,
			localICE,
			remoteICE,
			localICEEndpoint,
			remoteICEEndpoint,
			lastStatusUpdate,
			lastWireguardHandshake,
			toIEC(peerState.TransferReceived),
			toIEC(peerState.TransferSent),
		)

		peersString += peerString
	}
	return peersString
}

func skipDetailByFilters(peerState *proto.PeerState, isConnected bool) bool {
	statusEval := false
	ipEval := false
	nameEval := false

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

	if len(prefixNamesFilter) > 0 {
		for prefixNameFilter := range prefixNamesFilterMap {
			if !strings.HasPrefix(peerState.Fqdn, prefixNameFilter) {
				nameEval = true
				break
			}
		}
	}

	return statusEval || ipEval || nameEval
}

func toIEC(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}
