package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"github.com/netbirdio/netbird/client/anonymize"
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
	Latency                time.Duration    `json:"latency" yaml:"latency"`
	RosenpassEnabled       bool             `json:"quantumResistance" yaml:"quantumResistance"`
	Routes                 []string         `json:"routes" yaml:"routes"`
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

type nsServerGroupStateOutput struct {
	Servers []string `json:"servers" yaml:"servers"`
	Domains []string `json:"domains" yaml:"domains"`
	Enabled bool     `json:"enabled" yaml:"enabled"`
	Error   string   `json:"error" yaml:"error"`
}

type statusOutputOverview struct {
	Peers               peersStateOutput           `json:"peers" yaml:"peers"`
	CliVersion          string                     `json:"cliVersion" yaml:"cliVersion"`
	DaemonVersion       string                     `json:"daemonVersion" yaml:"daemonVersion"`
	ManagementState     managementStateOutput      `json:"management" yaml:"management"`
	SignalState         signalStateOutput          `json:"signal" yaml:"signal"`
	Relays              relayStateOutput           `json:"relays" yaml:"relays"`
	IP                  string                     `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey              string                     `json:"publicKey" yaml:"publicKey"`
	KernelInterface     bool                       `json:"usesKernelInterface" yaml:"usesKernelInterface"`
	FQDN                string                     `json:"fqdn" yaml:"fqdn"`
	RosenpassEnabled    bool                       `json:"quantumResistance" yaml:"quantumResistance"`
	RosenpassPermissive bool                       `json:"quantumResistancePermissive" yaml:"quantumResistancePermissive"`
	Routes              []string                   `json:"routes" yaml:"routes"`
	NSServerGroups      []nsServerGroupStateOutput `json:"dnsServers" yaml:"dnsServers"`
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

	ctx := internal.CtxInitState(cmd.Context())

	resp, err := getStatus(ctx)
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
		statusOutputString = parseGeneralSummary(outputInformationHolder, false, false, false)
	}

	if err != nil {
		return err
	}

	cmd.Print(statusOutputString)

	return nil
}

func getStatus(ctx context.Context) (*proto.StatusResponse, error) {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer conn.Close()

	resp, err := proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
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
		Peers:               peersOverview,
		CliVersion:          version.NetbirdVersion(),
		DaemonVersion:       resp.GetDaemonVersion(),
		ManagementState:     managementOverview,
		SignalState:         signalOverview,
		Relays:              relayOverview,
		IP:                  pbFullStatus.GetLocalPeerState().GetIP(),
		PubKey:              pbFullStatus.GetLocalPeerState().GetPubKey(),
		KernelInterface:     pbFullStatus.GetLocalPeerState().GetKernelInterface(),
		FQDN:                pbFullStatus.GetLocalPeerState().GetFqdn(),
		RosenpassEnabled:    pbFullStatus.GetLocalPeerState().GetRosenpassEnabled(),
		RosenpassPermissive: pbFullStatus.GetLocalPeerState().GetRosenpassPermissive(),
		Routes:              pbFullStatus.GetLocalPeerState().GetRoutes(),
		NSServerGroups:      mapNSGroups(pbFullStatus.GetDnsServers()),
	}

	if anonymizeFlag {
		anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
		anonymizeOverview(anonymizer, &overview)
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

func mapNSGroups(servers []*proto.NSGroupState) []nsServerGroupStateOutput {
	mappedNSGroups := make([]nsServerGroupStateOutput, 0, len(servers))
	for _, pbNsGroupServer := range servers {
		mappedNSGroups = append(mappedNSGroups, nsServerGroupStateOutput{
			Servers: pbNsGroupServer.GetServers(),
			Domains: pbNsGroupServer.GetDomains(),
			Enabled: pbNsGroupServer.GetEnabled(),
			Error:   pbNsGroupServer.GetError(),
		})
	}
	return mappedNSGroups
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
			Latency:                pbPeerState.GetLatency().AsDuration(),
			RosenpassEnabled:       pbPeerState.GetRosenpassEnabled(),
			Routes:                 pbPeerState.GetRoutes(),
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

func parseGeneralSummary(overview statusOutputOverview, showURL bool, showRelays bool, showNameServers bool) string {
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

	var relaysString string
	if showRelays {
		for _, relay := range overview.Relays.Details {
			available := "Available"
			reason := ""
			if !relay.Available {
				available = "Unavailable"
				reason = fmt.Sprintf(", reason: %s", relay.Error)
			}
			relaysString += fmt.Sprintf("\n  [%s] is %s%s", relay.URI, available, reason)
		}
	} else {
		relaysString = fmt.Sprintf("%d/%d Available", overview.Relays.Available, overview.Relays.Total)
	}

	routes := "-"
	if len(overview.Routes) > 0 {
		sort.Strings(overview.Routes)
		routes = strings.Join(overview.Routes, ", ")
	}

	var dnsServersString string
	if showNameServers {
		for _, nsServerGroup := range overview.NSServerGroups {
			enabled := "Available"
			if !nsServerGroup.Enabled {
				enabled = "Unavailable"
			}
			errorString := ""
			if nsServerGroup.Error != "" {
				errorString = fmt.Sprintf(", reason: %s", nsServerGroup.Error)
				errorString = strings.TrimSpace(errorString)
			}

			domainsString := strings.Join(nsServerGroup.Domains, ", ")
			if domainsString == "" {
				domainsString = "." // Show "." for the default zone
			}
			dnsServersString += fmt.Sprintf(
				"\n  [%s] for [%s] is %s%s",
				strings.Join(nsServerGroup.Servers, ", "),
				domainsString,
				enabled,
				errorString,
			)
		}
	} else {
		dnsServersString = fmt.Sprintf("%d/%d Available", countEnabled(overview.NSServerGroups), len(overview.NSServerGroups))
	}

	rosenpassEnabledStatus := "false"
	if overview.RosenpassEnabled {
		rosenpassEnabledStatus = "true"
		if overview.RosenpassPermissive {
			rosenpassEnabledStatus = "true (permissive)" //nolint:gosec
		}
	}

	peersCountString := fmt.Sprintf("%d/%d Connected", overview.Peers.Connected, overview.Peers.Total)

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	goarm := ""
	if goarch == "arm" {
		goarm = fmt.Sprintf(" (ARMv%s)", os.Getenv("GOARM"))
	}

	summary := fmt.Sprintf(
		"OS: %s\n"+
			"Daemon version: %s\n"+
			"CLI version: %s\n"+
			"Management: %s\n"+
			"Signal: %s\n"+
			"Relays: %s\n"+
			"Nameservers: %s\n"+
			"FQDN: %s\n"+
			"NetBird IP: %s\n"+
			"Interface type: %s\n"+
			"Quantum resistance: %s\n"+
			"Routes: %s\n"+
			"Peers count: %s\n",
		fmt.Sprintf("%s/%s%s", goos, goarch, goarm),
		overview.DaemonVersion,
		version.NetbirdVersion(),
		managementConnString,
		signalConnString,
		relaysString,
		dnsServersString,
		overview.FQDN,
		interfaceIP,
		interfaceTypeString,
		rosenpassEnabledStatus,
		routes,
		peersCountString,
	)
	return summary
}

func parseToFullDetailSummary(overview statusOutputOverview) string {
	parsedPeersString := parsePeers(overview.Peers, overview.RosenpassEnabled, overview.RosenpassPermissive)
	summary := parseGeneralSummary(overview, true, true, true)

	return fmt.Sprintf(
		"Peers detail:"+
			"%s\n"+
			"%s",
		parsedPeersString,
		summary,
	)
}

func parsePeers(peers peersStateOutput, rosenpassEnabled, rosenpassPermissive bool) string {
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

		rosenpassEnabledStatus := "false"
		if rosenpassEnabled {
			if peerState.RosenpassEnabled {
				rosenpassEnabledStatus = "true"
			} else {
				if rosenpassPermissive {
					rosenpassEnabledStatus = "false (remote didn't enable quantum resistance)"
				} else {
					rosenpassEnabledStatus = "false (connection won't work without a permissive mode)"
				}
			}
		} else {
			if peerState.RosenpassEnabled {
				rosenpassEnabledStatus = "false (connection might not work without a remote permissive mode)"
			}
		}

		routes := "-"
		if len(peerState.Routes) > 0 {
			sort.Strings(peerState.Routes)
			routes = strings.Join(peerState.Routes, ", ")
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
				"  Last WireGuard handshake: %s\n"+
				"  Transfer status (received/sent) %s/%s\n"+
				"  Quantum resistance: %s\n"+
				"  Routes: %s\n"+
				"  Latency: %s\n",
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
			timeAgo(peerState.LastStatusUpdate),
			timeAgo(peerState.LastWireguardHandshake),
			toIEC(peerState.TransferReceived),
			toIEC(peerState.TransferSent),
			rosenpassEnabledStatus,
			routes,
			peerState.Latency.String(),
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

func countEnabled(dnsServers []nsServerGroupStateOutput) int {
	count := 0
	for _, server := range dnsServers {
		if server.Enabled {
			count++
		}
	}
	return count
}

// timeAgo returns a string representing the duration since the provided time in a human-readable format.
func timeAgo(t time.Time) string {
	if t.IsZero() || t.Equal(time.Unix(0, 0)) {
		return "-"
	}
	duration := time.Since(t)
	switch {
	case duration < time.Second:
		return "Now"
	case duration < time.Minute:
		seconds := int(duration.Seconds())
		if seconds == 1 {
			return "1 second ago"
		}
		return fmt.Sprintf("%d seconds ago", seconds)
	case duration < time.Hour:
		minutes := int(duration.Minutes())
		seconds := int(duration.Seconds()) % 60
		if minutes == 1 {
			if seconds == 1 {
				return "1 minute, 1 second ago"
			} else if seconds > 0 {
				return fmt.Sprintf("1 minute, %d seconds ago", seconds)
			}
			return "1 minute ago"
		}
		if seconds > 0 {
			return fmt.Sprintf("%d minutes, %d seconds ago", minutes, seconds)
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	case duration < 24*time.Hour:
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		if hours == 1 {
			if minutes == 1 {
				return "1 hour, 1 minute ago"
			} else if minutes > 0 {
				return fmt.Sprintf("1 hour, %d minutes ago", minutes)
			}
			return "1 hour ago"
		}
		if minutes > 0 {
			return fmt.Sprintf("%d hours, %d minutes ago", hours, minutes)
		}
		return fmt.Sprintf("%d hours ago", hours)
	}

	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	if days == 1 {
		if hours == 1 {
			return "1 day, 1 hour ago"
		} else if hours > 0 {
			return fmt.Sprintf("1 day, %d hours ago", hours)
		}
		return "1 day ago"
	}
	if hours > 0 {
		return fmt.Sprintf("%d days, %d hours ago", days, hours)
	}
	return fmt.Sprintf("%d days ago", days)
}

func anonymizePeerDetail(a *anonymize.Anonymizer, peer *peerStateDetailOutput) {
	peer.FQDN = a.AnonymizeDomain(peer.FQDN)
	if localIP, port, err := net.SplitHostPort(peer.IceCandidateEndpoint.Local); err == nil {
		peer.IceCandidateEndpoint.Local = fmt.Sprintf("%s:%s", a.AnonymizeIPString(localIP), port)
	}
	if remoteIP, port, err := net.SplitHostPort(peer.IceCandidateEndpoint.Remote); err == nil {
		peer.IceCandidateEndpoint.Remote = fmt.Sprintf("%s:%s", a.AnonymizeIPString(remoteIP), port)
	}
	for i, route := range peer.Routes {
		peer.Routes[i] = a.AnonymizeIPString(route)
	}

	for i, route := range peer.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err == nil {
			ip := a.AnonymizeIPString(prefix.Addr().String())
			peer.Routes[i] = fmt.Sprintf("%s/%d", ip, prefix.Bits())
		}
	}
}

func anonymizeOverview(a *anonymize.Anonymizer, overview *statusOutputOverview) {
	for i, peer := range overview.Peers.Details {
		peer := peer
		anonymizePeerDetail(a, &peer)
		overview.Peers.Details[i] = peer
	}

	overview.ManagementState.URL = a.AnonymizeURI(overview.ManagementState.URL)
	overview.ManagementState.Error = a.AnonymizeString(overview.ManagementState.Error)
	overview.SignalState.URL = a.AnonymizeURI(overview.SignalState.URL)
	overview.SignalState.Error = a.AnonymizeString(overview.SignalState.Error)

	overview.IP = a.AnonymizeIPString(overview.IP)
	for i, detail := range overview.Relays.Details {
		detail.URI = a.AnonymizeURI(detail.URI)
		detail.Error = a.AnonymizeString(detail.Error)
		overview.Relays.Details[i] = detail
	}

	for i, nsGroup := range overview.NSServerGroups {
		for j, domain := range nsGroup.Domains {
			overview.NSServerGroups[i].Domains[j] = a.AnonymizeDomain(domain)
		}
		for j, ns := range nsGroup.Servers {
			host, port, err := net.SplitHostPort(ns)
			if err == nil {
				overview.NSServerGroups[i].Servers[j] = fmt.Sprintf("%s:%s", a.AnonymizeIPString(host), port)
			}
		}
	}

	for i, route := range overview.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err == nil {
			ip := a.AnonymizeIPString(prefix.Addr().String())
			overview.Routes[i] = fmt.Sprintf("%s/%d", ip, prefix.Bits())
		}
	}

	overview.FQDN = a.AnonymizeDomain(overview.FQDN)
}
