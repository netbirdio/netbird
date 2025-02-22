package status

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

type PeerStateDetailOutput struct {
	FQDN                   string           `json:"fqdn" yaml:"fqdn"`
	IP                     string           `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey                 string           `json:"publicKey" yaml:"publicKey"`
	Status                 string           `json:"status" yaml:"status"`
	LastStatusUpdate       time.Time        `json:"lastStatusUpdate" yaml:"lastStatusUpdate"`
	ConnType               string           `json:"connectionType" yaml:"connectionType"`
	IceCandidateType       IceCandidateType `json:"iceCandidateType" yaml:"iceCandidateType"`
	IceCandidateEndpoint   IceCandidateType `json:"iceCandidateEndpoint" yaml:"iceCandidateEndpoint"`
	RelayAddress           string           `json:"relayAddress" yaml:"relayAddress"`
	LastWireguardHandshake time.Time        `json:"lastWireguardHandshake" yaml:"lastWireguardHandshake"`
	TransferReceived       int64            `json:"transferReceived" yaml:"transferReceived"`
	TransferSent           int64            `json:"transferSent" yaml:"transferSent"`
	Latency                time.Duration    `json:"latency" yaml:"latency"`
	RosenpassEnabled       bool             `json:"quantumResistance" yaml:"quantumResistance"`
	Networks               []string         `json:"networks" yaml:"networks"`
}

type PeersStateOutput struct {
	Total     int                     `json:"total" yaml:"total"`
	Connected int                     `json:"connected" yaml:"connected"`
	Details   []PeerStateDetailOutput `json:"details" yaml:"details"`
}

type SignalStateOutput struct {
	URL       string `json:"url" yaml:"url"`
	Connected bool   `json:"connected" yaml:"connected"`
	Error     string `json:"error" yaml:"error"`
}

type ManagementStateOutput struct {
	URL       string `json:"url" yaml:"url"`
	Connected bool   `json:"connected" yaml:"connected"`
	Error     string `json:"error" yaml:"error"`
}

type RelayStateOutputDetail struct {
	URI       string `json:"uri" yaml:"uri"`
	Available bool   `json:"available" yaml:"available"`
	Error     string `json:"error" yaml:"error"`
}

type RelayStateOutput struct {
	Total     int                      `json:"total" yaml:"total"`
	Available int                      `json:"available" yaml:"available"`
	Details   []RelayStateOutputDetail `json:"details" yaml:"details"`
}

type IceCandidateType struct {
	Local  string `json:"local" yaml:"local"`
	Remote string `json:"remote" yaml:"remote"`
}

type NsServerGroupStateOutput struct {
	Servers []string `json:"servers" yaml:"servers"`
	Domains []string `json:"domains" yaml:"domains"`
	Enabled bool     `json:"enabled" yaml:"enabled"`
	Error   string   `json:"error" yaml:"error"`
}

type OutputOverview struct {
	Peers               PeersStateOutput           `json:"peers" yaml:"peers"`
	CliVersion          string                     `json:"cliVersion" yaml:"cliVersion"`
	DaemonVersion       string                     `json:"daemonVersion" yaml:"daemonVersion"`
	ManagementState     ManagementStateOutput      `json:"management" yaml:"management"`
	SignalState         SignalStateOutput          `json:"signal" yaml:"signal"`
	Relays              RelayStateOutput           `json:"relays" yaml:"relays"`
	IP                  string                     `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey              string                     `json:"publicKey" yaml:"publicKey"`
	KernelInterface     bool                       `json:"usesKernelInterface" yaml:"usesKernelInterface"`
	FQDN                string                     `json:"fqdn" yaml:"fqdn"`
	RosenpassEnabled    bool                       `json:"quantumResistance" yaml:"quantumResistance"`
	RosenpassPermissive bool                       `json:"quantumResistancePermissive" yaml:"quantumResistancePermissive"`
	Networks            []string                   `json:"networks" yaml:"networks"`
	NSServerGroups      []NsServerGroupStateOutput `json:"dnsServers" yaml:"dnsServers"`
	Events              []SystemEventOutput        `json:"events" yaml:"events"`
}

func ConvertToStatusOutputOverview(resp *proto.StatusResponse, anon bool, statusFilter string, prefixNamesFilter []string, prefixNamesFilterMap map[string]struct{}, ipsFilter map[string]struct{}) OutputOverview {
	pbFullStatus := resp.GetFullStatus()

	managementState := pbFullStatus.GetManagementState()
	managementOverview := ManagementStateOutput{
		URL:       managementState.GetURL(),
		Connected: managementState.GetConnected(),
		Error:     managementState.Error,
	}

	signalState := pbFullStatus.GetSignalState()
	signalOverview := SignalStateOutput{
		URL:       signalState.GetURL(),
		Connected: signalState.GetConnected(),
		Error:     signalState.Error,
	}

	relayOverview := mapRelays(pbFullStatus.GetRelays())
	peersOverview := mapPeers(resp.GetFullStatus().GetPeers(), statusFilter, prefixNamesFilter, prefixNamesFilterMap, ipsFilter)

	overview := OutputOverview{
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
		Networks:            pbFullStatus.GetLocalPeerState().GetNetworks(),
		NSServerGroups:      mapNSGroups(pbFullStatus.GetDnsServers()),
		Events:              mapEvents(pbFullStatus.GetEvents()),
	}

	if anon {
		anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
		anonymizeOverview(anonymizer, &overview)
	}

	return overview
}

func mapRelays(relays []*proto.RelayState) RelayStateOutput {
	var relayStateDetail []RelayStateOutputDetail

	var relaysAvailable int
	for _, relay := range relays {
		available := relay.GetAvailable()
		relayStateDetail = append(relayStateDetail,
			RelayStateOutputDetail{
				URI:       relay.URI,
				Available: available,
				Error:     relay.GetError(),
			},
		)

		if available {
			relaysAvailable++
		}
	}

	return RelayStateOutput{
		Total:     len(relays),
		Available: relaysAvailable,
		Details:   relayStateDetail,
	}
}

func mapNSGroups(servers []*proto.NSGroupState) []NsServerGroupStateOutput {
	mappedNSGroups := make([]NsServerGroupStateOutput, 0, len(servers))
	for _, pbNsGroupServer := range servers {
		mappedNSGroups = append(mappedNSGroups, NsServerGroupStateOutput{
			Servers: pbNsGroupServer.GetServers(),
			Domains: pbNsGroupServer.GetDomains(),
			Enabled: pbNsGroupServer.GetEnabled(),
			Error:   pbNsGroupServer.GetError(),
		})
	}
	return mappedNSGroups
}

func mapPeers(
	peers []*proto.PeerState,
	statusFilter string,
	prefixNamesFilter []string,
	prefixNamesFilterMap map[string]struct{},
	ipsFilter map[string]struct{},
) PeersStateOutput {
	var peersStateDetail []PeerStateDetailOutput
	peersConnected := 0
	for _, pbPeerState := range peers {
		localICE := ""
		remoteICE := ""
		localICEEndpoint := ""
		remoteICEEndpoint := ""
		relayServerAddress := ""
		connType := ""
		lastHandshake := time.Time{}
		transferReceived := int64(0)
		transferSent := int64(0)

		isPeerConnected := pbPeerState.ConnStatus == peer.StatusConnected.String()
		if skipDetailByFilters(pbPeerState, isPeerConnected, statusFilter, prefixNamesFilter, prefixNamesFilterMap, ipsFilter) {
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
			relayServerAddress = pbPeerState.GetRelayAddress()
			lastHandshake = pbPeerState.GetLastWireguardHandshake().AsTime().Local()
			transferReceived = pbPeerState.GetBytesRx()
			transferSent = pbPeerState.GetBytesTx()
		}

		timeLocal := pbPeerState.GetConnStatusUpdate().AsTime().Local()
		peerState := PeerStateDetailOutput{
			IP:               pbPeerState.GetIP(),
			PubKey:           pbPeerState.GetPubKey(),
			Status:           pbPeerState.GetConnStatus(),
			LastStatusUpdate: timeLocal,
			ConnType:         connType,
			IceCandidateType: IceCandidateType{
				Local:  localICE,
				Remote: remoteICE,
			},
			IceCandidateEndpoint: IceCandidateType{
				Local:  localICEEndpoint,
				Remote: remoteICEEndpoint,
			},
			RelayAddress:           relayServerAddress,
			FQDN:                   pbPeerState.GetFqdn(),
			LastWireguardHandshake: lastHandshake,
			TransferReceived:       transferReceived,
			TransferSent:           transferSent,
			Latency:                pbPeerState.GetLatency().AsDuration(),
			RosenpassEnabled:       pbPeerState.GetRosenpassEnabled(),
			Networks:               pbPeerState.GetNetworks(),
		}

		peersStateDetail = append(peersStateDetail, peerState)
	}

	sortPeersByIP(peersStateDetail)

	peersOverview := PeersStateOutput{
		Total:     len(peersStateDetail),
		Connected: peersConnected,
		Details:   peersStateDetail,
	}
	return peersOverview
}

func sortPeersByIP(peersStateDetail []PeerStateDetailOutput) {
	if len(peersStateDetail) > 0 {
		sort.SliceStable(peersStateDetail, func(i, j int) bool {
			iAddr, _ := netip.ParseAddr(peersStateDetail[i].IP)
			jAddr, _ := netip.ParseAddr(peersStateDetail[j].IP)
			return iAddr.Compare(jAddr) == -1
		})
	}
}

func ParseToJSON(overview OutputOverview) (string, error) {
	jsonBytes, err := json.Marshal(overview)
	if err != nil {
		return "", fmt.Errorf("json marshal failed")
	}
	return string(jsonBytes), err
}

func ParseToYAML(overview OutputOverview) (string, error) {
	yamlBytes, err := yaml.Marshal(overview)
	if err != nil {
		return "", fmt.Errorf("yaml marshal failed")
	}
	return string(yamlBytes), nil
}

func ParseGeneralSummary(overview OutputOverview, showURL bool, showRelays bool, showNameServers bool) string {
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

	networks := "-"
	if len(overview.Networks) > 0 {
		sort.Strings(overview.Networks)
		networks = strings.Join(overview.Networks, ", ")
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
			"Networks: %s\n"+
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
		networks,
		peersCountString,
	)
	return summary
}

func ParseToFullDetailSummary(overview OutputOverview) string {
	parsedPeersString := parsePeers(overview.Peers, overview.RosenpassEnabled, overview.RosenpassPermissive)
	parsedEventsString := parseEvents(overview.Events)
	summary := ParseGeneralSummary(overview, true, true, true)

	return fmt.Sprintf(
		"Peers detail:"+
			"%s\n"+
			"Events:"+
			"%s\n"+
			"%s",
		parsedPeersString,
		parsedEventsString,
		summary,
	)
}

func parsePeers(peers PeersStateOutput, rosenpassEnabled, rosenpassPermissive bool) string {
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

		networks := "-"
		if len(peerState.Networks) > 0 {
			sort.Strings(peerState.Networks)
			networks = strings.Join(peerState.Networks, ", ")
		}

		peerString := fmt.Sprintf(
			"\n %s:\n"+
				"  NetBird IP: %s\n"+
				"  Public key: %s\n"+
				"  Status: %s\n"+
				"  -- detail --\n"+
				"  Connection type: %s\n"+
				"  ICE candidate (Local/Remote): %s/%s\n"+
				"  ICE candidate endpoints (Local/Remote): %s/%s\n"+
				"  Relay server address: %s\n"+
				"  Last connection update: %s\n"+
				"  Last WireGuard handshake: %s\n"+
				"  Transfer status (received/sent) %s/%s\n"+
				"  Quantum resistance: %s\n"+
				"  Networks: %s\n"+
				"  Latency: %s\n",
			peerState.FQDN,
			peerState.IP,
			peerState.PubKey,
			peerState.Status,
			peerState.ConnType,
			localICE,
			remoteICE,
			localICEEndpoint,
			remoteICEEndpoint,
			peerState.RelayAddress,
			timeAgo(peerState.LastStatusUpdate),
			timeAgo(peerState.LastWireguardHandshake),
			toIEC(peerState.TransferReceived),
			toIEC(peerState.TransferSent),
			rosenpassEnabledStatus,
			networks,
			peerState.Latency.String(),
		)

		peersString += peerString
	}
	return peersString
}

func skipDetailByFilters(
	peerState *proto.PeerState,
	isConnected bool,
	statusFilter string,
	prefixNamesFilter []string,
	prefixNamesFilterMap map[string]struct{},
	ipsFilter map[string]struct{},
) bool {
	statusEval := false
	ipEval := false
	nameEval := true

	if statusFilter != "" {
		lowerStatusFilter := strings.ToLower(statusFilter)
		if lowerStatusFilter == "disconnected" && isConnected {
			statusEval = true
		} else if lowerStatusFilter == "connected" && !isConnected {
			statusEval = true
		}
	}

	if len(ipsFilter) > 0 {
		_, ok := ipsFilter[peerState.IP]
		if !ok {
			ipEval = true
		}
	}

	if len(prefixNamesFilter) > 0 {
		for prefixNameFilter := range prefixNamesFilterMap {
			if strings.HasPrefix(peerState.Fqdn, prefixNameFilter) {
				nameEval = false
				break
			}
		}
	} else {
		nameEval = false
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

func countEnabled(dnsServers []NsServerGroupStateOutput) int {
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

func anonymizePeerDetail(a *anonymize.Anonymizer, peer *PeerStateDetailOutput) {
	peer.FQDN = a.AnonymizeDomain(peer.FQDN)
	if localIP, port, err := net.SplitHostPort(peer.IceCandidateEndpoint.Local); err == nil {
		peer.IceCandidateEndpoint.Local = fmt.Sprintf("%s:%s", a.AnonymizeIPString(localIP), port)
	}
	if remoteIP, port, err := net.SplitHostPort(peer.IceCandidateEndpoint.Remote); err == nil {
		peer.IceCandidateEndpoint.Remote = fmt.Sprintf("%s:%s", a.AnonymizeIPString(remoteIP), port)
	}

	peer.RelayAddress = a.AnonymizeURI(peer.RelayAddress)

	for i, route := range peer.Networks {
		peer.Networks[i] = a.AnonymizeIPString(route)
	}

	for i, route := range peer.Networks {
		peer.Networks[i] = a.AnonymizeRoute(route)
	}
}

func anonymizeOverview(a *anonymize.Anonymizer, overview *OutputOverview) {
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

	for i, route := range overview.Networks {
		overview.Networks[i] = a.AnonymizeRoute(route)
	}

	overview.FQDN = a.AnonymizeDomain(overview.FQDN)

	for i, event := range overview.Events {
		overview.Events[i].Message = a.AnonymizeString(event.Message)
		overview.Events[i].UserMessage = a.AnonymizeString(event.UserMessage)

		for k, v := range event.Metadata {
			event.Metadata[k] = a.AnonymizeString(v)
		}
	}
}
