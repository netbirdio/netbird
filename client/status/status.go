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

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/peer"
	probeRelay "github.com/netbirdio/netbird/client/internal/relay"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/shared/management/domain"
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

type SSHSessionOutput struct {
	Username      string   `json:"username" yaml:"username"`
	RemoteAddress string   `json:"remoteAddress" yaml:"remoteAddress"`
	Command       string   `json:"command" yaml:"command"`
	JWTUsername   string   `json:"jwtUsername,omitempty" yaml:"jwtUsername,omitempty"`
	PortForwards  []string `json:"portForwards,omitempty" yaml:"portForwards,omitempty"`
}

type SSHServerStateOutput struct {
	Enabled  bool               `json:"enabled" yaml:"enabled"`
	Sessions []SSHSessionOutput `json:"sessions" yaml:"sessions"`
}

type OutputOverview struct {
	Peers                   PeersStateOutput           `json:"peers" yaml:"peers"`
	CliVersion              string                     `json:"cliVersion" yaml:"cliVersion"`
	DaemonVersion           string                     `json:"daemonVersion" yaml:"daemonVersion"`
	ManagementState         ManagementStateOutput      `json:"management" yaml:"management"`
	SignalState             SignalStateOutput          `json:"signal" yaml:"signal"`
	Relays                  RelayStateOutput           `json:"relays" yaml:"relays"`
	IP                      string                     `json:"netbirdIp" yaml:"netbirdIp"`
	PubKey                  string                     `json:"publicKey" yaml:"publicKey"`
	KernelInterface         bool                       `json:"usesKernelInterface" yaml:"usesKernelInterface"`
	FQDN                    string                     `json:"fqdn" yaml:"fqdn"`
	RosenpassEnabled        bool                       `json:"quantumResistance" yaml:"quantumResistance"`
	RosenpassPermissive     bool                       `json:"quantumResistancePermissive" yaml:"quantumResistancePermissive"`
	Networks                []string                   `json:"networks" yaml:"networks"`
	NumberOfForwardingRules int                        `json:"forwardingRules" yaml:"forwardingRules"`
	NSServerGroups          []NsServerGroupStateOutput `json:"dnsServers" yaml:"dnsServers"`
	Events                  []SystemEventOutput        `json:"events" yaml:"events"`
	LazyConnectionEnabled   bool                       `json:"lazyConnectionEnabled" yaml:"lazyConnectionEnabled"`
	ProfileName             string                     `json:"profileName" yaml:"profileName"`
	SSHServerState          SSHServerStateOutput       `json:"sshServer" yaml:"sshServer"`
}

func ConvertToStatusOutputOverview(pbFullStatus *proto.FullStatus, anon bool, daemonVersion string, statusFilter string, prefixNamesFilter []string, prefixNamesFilterMap map[string]struct{}, ipsFilter map[string]struct{}, connectionTypeFilter string, profName string) OutputOverview {
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
	sshServerOverview := mapSSHServer(pbFullStatus.GetSshServerState())
	peersOverview := mapPeers(pbFullStatus.GetPeers(), statusFilter, prefixNamesFilter, prefixNamesFilterMap, ipsFilter, connectionTypeFilter)

	overview := OutputOverview{
		Peers:                   peersOverview,
		CliVersion:              version.NetbirdVersion(),
		DaemonVersion:           daemonVersion,
		ManagementState:         managementOverview,
		SignalState:             signalOverview,
		Relays:                  relayOverview,
		IP:                      pbFullStatus.GetLocalPeerState().GetIP(),
		PubKey:                  pbFullStatus.GetLocalPeerState().GetPubKey(),
		KernelInterface:         pbFullStatus.GetLocalPeerState().GetKernelInterface(),
		FQDN:                    pbFullStatus.GetLocalPeerState().GetFqdn(),
		RosenpassEnabled:        pbFullStatus.GetLocalPeerState().GetRosenpassEnabled(),
		RosenpassPermissive:     pbFullStatus.GetLocalPeerState().GetRosenpassPermissive(),
		Networks:                pbFullStatus.GetLocalPeerState().GetNetworks(),
		NumberOfForwardingRules: int(pbFullStatus.GetNumberOfForwardingRules()),
		NSServerGroups:          mapNSGroups(pbFullStatus.GetDnsServers()),
		Events:                  mapEvents(pbFullStatus.GetEvents()),
		LazyConnectionEnabled:   pbFullStatus.GetLazyConnectionEnabled(),
		ProfileName:             profName,
		SSHServerState:          sshServerOverview,
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

func mapSSHServer(sshServerState *proto.SSHServerState) SSHServerStateOutput {
	if sshServerState == nil {
		return SSHServerStateOutput{
			Enabled:  false,
			Sessions: []SSHSessionOutput{},
		}
	}

	sessions := make([]SSHSessionOutput, 0, len(sshServerState.GetSessions()))
	for _, session := range sshServerState.GetSessions() {
		sessions = append(sessions, SSHSessionOutput{
			Username:      session.GetUsername(),
			RemoteAddress: session.GetRemoteAddress(),
			Command:       session.GetCommand(),
			JWTUsername:   session.GetJwtUsername(),
			PortForwards:  session.GetPortForwards(),
		})
	}

	return SSHServerStateOutput{
		Enabled:  sshServerState.GetEnabled(),
		Sessions: sessions,
	}
}

func mapPeers(
	peers []*proto.PeerState,
	statusFilter string,
	prefixNamesFilter []string,
	prefixNamesFilterMap map[string]struct{},
	ipsFilter map[string]struct{},
	connectionTypeFilter string,
) PeersStateOutput {
	var peersStateDetail []PeerStateDetailOutput
	peersConnected := 0
	for _, pbPeerState := range peers {
		localICE := ""
		remoteICE := ""
		localICEEndpoint := ""
		remoteICEEndpoint := ""
		relayServerAddress := ""
		connType := "-"
		lastHandshake := time.Time{}
		transferReceived := int64(0)
		transferSent := int64(0)

		isPeerConnected := pbPeerState.ConnStatus == peer.StatusConnected.String()

		if isPeerConnected {
			connType = "P2P"
			if pbPeerState.Relayed {
				connType = "Relayed"
			}
		}

		if skipDetailByFilters(pbPeerState, pbPeerState.ConnStatus, statusFilter, prefixNamesFilter, prefixNamesFilterMap, ipsFilter, connectionTypeFilter, connType) {
			continue
		}
		if isPeerConnected {
			peersConnected++

			localICE = pbPeerState.GetLocalIceCandidateType()
			remoteICE = pbPeerState.GetRemoteIceCandidateType()
			localICEEndpoint = pbPeerState.GetLocalIceCandidateEndpoint()
			remoteICEEndpoint = pbPeerState.GetRemoteIceCandidateEndpoint()
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

// JSON returns the status overview as a JSON string.
func (o *OutputOverview) JSON() (string, error) {
	jsonBytes, err := json.Marshal(o)
	if err != nil {
		return "", fmt.Errorf("json marshal failed")
	}
	return string(jsonBytes), err
}

// YAML returns the status overview as a YAML string.
func (o *OutputOverview) YAML() (string, error) {
	yamlBytes, err := yaml.Marshal(o)
	if err != nil {
		return "", fmt.Errorf("yaml marshal failed")
	}
	return string(yamlBytes), nil
}

// GeneralSummary returns a general summary of the status overview.
func (o *OutputOverview) GeneralSummary(showURL bool, showRelays bool, showNameServers bool, showSSHSessions bool) string {
	var managementConnString string
	if o.ManagementState.Connected {
		managementConnString = "Connected"
		if showURL {
			managementConnString = fmt.Sprintf("%s to %s", managementConnString, o.ManagementState.URL)
		}
	} else {
		managementConnString = "Disconnected"
		if o.ManagementState.Error != "" {
			managementConnString = fmt.Sprintf("%s, reason: %s", managementConnString, o.ManagementState.Error)
		}
	}

	var signalConnString string
	if o.SignalState.Connected {
		signalConnString = "Connected"
		if showURL {
			signalConnString = fmt.Sprintf("%s to %s", signalConnString, o.SignalState.URL)
		}
	} else {
		signalConnString = "Disconnected"
		if o.SignalState.Error != "" {
			signalConnString = fmt.Sprintf("%s, reason: %s", signalConnString, o.SignalState.Error)
		}
	}

	interfaceTypeString := "Userspace"
	interfaceIP := o.IP
	if o.KernelInterface {
		interfaceTypeString = "Kernel"
	} else if o.IP == "" {
		interfaceTypeString = "N/A"
		interfaceIP = "N/A"
	}

	var relaysString string
	if showRelays {
		for _, relay := range o.Relays.Details {
			available := "Available"
			reason := ""

			if !relay.Available {
				if relay.Error == probeRelay.ErrCheckInProgress.Error() {
					available = "Checking..."
				} else {
					available = "Unavailable"
					reason = fmt.Sprintf(", reason: %s", relay.Error)
				}
			}

			relaysString += fmt.Sprintf("\n  [%s] is %s%s", relay.URI, available, reason)
		}
	} else {
		relaysString = fmt.Sprintf("%d/%d Available", o.Relays.Available, o.Relays.Total)
	}

	networks := "-"
	if len(o.Networks) > 0 {
		sort.Strings(o.Networks)
		networks = strings.Join(o.Networks, ", ")
	}

	var dnsServersString string
	if showNameServers {
		for _, nsServerGroup := range o.NSServerGroups {
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
		dnsServersString = fmt.Sprintf("%d/%d Available", countEnabled(o.NSServerGroups), len(o.NSServerGroups))
	}

	rosenpassEnabledStatus := "false"
	if o.RosenpassEnabled {
		rosenpassEnabledStatus = "true"
		if o.RosenpassPermissive {
			rosenpassEnabledStatus = "true (permissive)" //nolint:gosec
		}
	}

	lazyConnectionEnabledStatus := "false"
	if o.LazyConnectionEnabled {
		lazyConnectionEnabledStatus = "true"
	}

	sshServerStatus := "Disabled"
	if o.SSHServerState.Enabled {
		sessionCount := len(o.SSHServerState.Sessions)
		if sessionCount > 0 {
			sessionWord := "session"
			if sessionCount > 1 {
				sessionWord = "sessions"
			}
			sshServerStatus = fmt.Sprintf("Enabled (%d active %s)", sessionCount, sessionWord)
		} else {
			sshServerStatus = "Enabled"
		}

		if showSSHSessions && sessionCount > 0 {
			for _, session := range o.SSHServerState.Sessions {
				var sessionDisplay string
				if session.JWTUsername != "" {
					sessionDisplay = fmt.Sprintf("[%s@%s -> %s] %s",
						session.JWTUsername,
						session.RemoteAddress,
						session.Username,
						session.Command,
					)
				} else {
					sessionDisplay = fmt.Sprintf("[%s@%s] %s",
						session.Username,
						session.RemoteAddress,
						session.Command,
					)
				}
				sshServerStatus += "\n  " + sessionDisplay
				for _, pf := range session.PortForwards {
					sshServerStatus += "\n    " + pf
				}
			}
		}
	}

	peersCountString := fmt.Sprintf("%d/%d Connected", o.Peers.Connected, o.Peers.Total)

	var forwardingRulesString string
	if o.NumberOfForwardingRules > 0 {
		forwardingRulesString = fmt.Sprintf("Forwarding rules: %d\n", o.NumberOfForwardingRules)
	}

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
			"Profile: %s\n"+
			"Management: %s\n"+
			"Signal: %s\n"+
			"Relays: %s\n"+
			"Nameservers: %s\n"+
			"FQDN: %s\n"+
			"NetBird IP: %s\n"+
			"Interface type: %s\n"+
			"Quantum resistance: %s\n"+
			"Lazy connection: %s\n"+
			"SSH Server: %s\n"+
			"Networks: %s\n"+
			"%s"+
			"Peers count: %s\n",
		fmt.Sprintf("%s/%s%s", goos, goarch, goarm),
		o.DaemonVersion,
		version.NetbirdVersion(),
		o.ProfileName,
		managementConnString,
		signalConnString,
		relaysString,
		dnsServersString,
		domain.Domain(o.FQDN).SafeString(),
		interfaceIP,
		interfaceTypeString,
		rosenpassEnabledStatus,
		lazyConnectionEnabledStatus,
		sshServerStatus,
		networks,
		forwardingRulesString,
		peersCountString,
	)
	return summary
}

// FullDetailSummary returns a full detailed summary with peer details and events.
func (o *OutputOverview) FullDetailSummary() string {
	parsedPeersString := parsePeers(o.Peers, o.RosenpassEnabled, o.RosenpassPermissive)
	parsedEventsString := parseEvents(o.Events)
	summary := o.GeneralSummary(true, true, true, true)

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

func ToProtoFullStatus(fullStatus peer.FullStatus) *proto.FullStatus {
	pbFullStatus := proto.FullStatus{
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
		LocalPeerState:  &proto.LocalPeerState{},
		Peers:           []*proto.PeerState{},
	}

	pbFullStatus.ManagementState.URL = fullStatus.ManagementState.URL
	pbFullStatus.ManagementState.Connected = fullStatus.ManagementState.Connected
	if err := fullStatus.ManagementState.Error; err != nil {
		pbFullStatus.ManagementState.Error = err.Error()
	}

	pbFullStatus.SignalState.URL = fullStatus.SignalState.URL
	pbFullStatus.SignalState.Connected = fullStatus.SignalState.Connected
	if err := fullStatus.SignalState.Error; err != nil {
		pbFullStatus.SignalState.Error = err.Error()
	}

	pbFullStatus.LocalPeerState.IP = fullStatus.LocalPeerState.IP
	pbFullStatus.LocalPeerState.PubKey = fullStatus.LocalPeerState.PubKey
	pbFullStatus.LocalPeerState.KernelInterface = fullStatus.LocalPeerState.KernelInterface
	pbFullStatus.LocalPeerState.Fqdn = fullStatus.LocalPeerState.FQDN
	pbFullStatus.LocalPeerState.RosenpassPermissive = fullStatus.RosenpassState.Permissive
	pbFullStatus.LocalPeerState.RosenpassEnabled = fullStatus.RosenpassState.Enabled
	pbFullStatus.LocalPeerState.Networks = maps.Keys(fullStatus.LocalPeerState.Routes)
	pbFullStatus.NumberOfForwardingRules = int32(fullStatus.NumOfForwardingRules)
	pbFullStatus.LazyConnectionEnabled = fullStatus.LazyConnectionEnabled

	for _, peerState := range fullStatus.Peers {
		pbPeerState := &proto.PeerState{
			IP:                         peerState.IP,
			PubKey:                     peerState.PubKey,
			ConnStatus:                 peerState.ConnStatus.String(),
			ConnStatusUpdate:           timestamppb.New(peerState.ConnStatusUpdate),
			Relayed:                    peerState.Relayed,
			LocalIceCandidateType:      peerState.LocalIceCandidateType,
			RemoteIceCandidateType:     peerState.RemoteIceCandidateType,
			LocalIceCandidateEndpoint:  peerState.LocalIceCandidateEndpoint,
			RemoteIceCandidateEndpoint: peerState.RemoteIceCandidateEndpoint,
			RelayAddress:               peerState.RelayServerAddress,
			Fqdn:                       peerState.FQDN,
			LastWireguardHandshake:     timestamppb.New(peerState.LastWireguardHandshake),
			BytesRx:                    peerState.BytesRx,
			BytesTx:                    peerState.BytesTx,
			RosenpassEnabled:           peerState.RosenpassEnabled,
			Networks:                   maps.Keys(peerState.GetRoutes()),
			Latency:                    durationpb.New(peerState.Latency),
			SshHostKey:                 peerState.SSHHostKey,
		}
		pbFullStatus.Peers = append(pbFullStatus.Peers, pbPeerState)
	}

	for _, relayState := range fullStatus.Relays {
		pbRelayState := &proto.RelayState{
			URI:       relayState.URI,
			Available: relayState.Err == nil,
		}
		if err := relayState.Err; err != nil {
			pbRelayState.Error = err.Error()
		}
		pbFullStatus.Relays = append(pbFullStatus.Relays, pbRelayState)
	}

	for _, dnsState := range fullStatus.NSGroupStates {
		var err string
		if dnsState.Error != nil {
			err = dnsState.Error.Error()
		}

		var servers []string
		for _, server := range dnsState.Servers {
			servers = append(servers, server.String())
		}

		pbDnsState := &proto.NSGroupState{
			Servers: servers,
			Domains: dnsState.Domains,
			Enabled: dnsState.Enabled,
			Error:   err,
		}
		pbFullStatus.DnsServers = append(pbFullStatus.DnsServers, pbDnsState)
	}

	return &pbFullStatus
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
			domain.Domain(peerState.FQDN).SafeString(),
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

func skipDetailByFilters(peerState *proto.PeerState, peerStatus string, statusFilter string, prefixNamesFilter []string, prefixNamesFilterMap map[string]struct{}, ipsFilter map[string]struct{}, connectionTypeFilter, connType string) bool {
	statusEval := false
	ipEval := false
	nameEval := true
	connectionTypeEval := false

	if statusFilter != "" {
		if !strings.EqualFold(peerStatus, statusFilter) {
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
	if connectionTypeFilter != "" && !strings.EqualFold(connType, connectionTypeFilter) {
		connectionTypeEval = true
	}

	return statusEval || ipEval || nameEval || connectionTypeEval
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

	for i, session := range overview.SSHServerState.Sessions {
		if host, port, err := net.SplitHostPort(session.RemoteAddress); err == nil {
			overview.SSHServerState.Sessions[i].RemoteAddress = fmt.Sprintf("%s:%s", a.AnonymizeIPString(host), port)
		} else {
			overview.SSHServerState.Sessions[i].RemoteAddress = a.AnonymizeIPString(session.RemoteAddress)
		}
		overview.SSHServerState.Sessions[i].Command = a.AnonymizeString(session.Command)
	}
}
