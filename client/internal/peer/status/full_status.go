package status

import (
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/relay"
	"github.com/netbirdio/netbird/client/proto"
)

// FullStatus contains the full state held by the Recorder instance
type FullStatus struct {
	Peers                 []State
	ManagementState       ManagementState
	SignalState           SignalState
	LocalPeerState        LocalPeerState
	RosenpassState        RosenpassState
	Relays                []relay.ProbeResult
	NSGroupStates         []NSGroupState
	NumOfForwardingRules  int
	LazyConnectionEnabled bool
	Events                []*proto.SystemEvent
}

// ToProto converts FullStatus to proto.FullStatus.
func (fs FullStatus) ToProto() *proto.FullStatus {
	pbFullStatus := proto.FullStatus{
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
		LocalPeerState:  &proto.LocalPeerState{},
		Peers:           []*proto.PeerState{},
	}

	pbFullStatus.ManagementState.URL = fs.ManagementState.URL
	pbFullStatus.ManagementState.Connected = fs.ManagementState.Connected
	if err := fs.ManagementState.Error; err != nil {
		pbFullStatus.ManagementState.Error = err.Error()
	}

	pbFullStatus.SignalState.URL = fs.SignalState.URL
	pbFullStatus.SignalState.Connected = fs.SignalState.Connected
	if err := fs.SignalState.Error; err != nil {
		pbFullStatus.SignalState.Error = err.Error()
	}

	pbFullStatus.LocalPeerState.IP = fs.LocalPeerState.IP
	pbFullStatus.LocalPeerState.Ipv6 = fs.LocalPeerState.IPv6
	pbFullStatus.LocalPeerState.PubKey = fs.LocalPeerState.PubKey
	pbFullStatus.LocalPeerState.KernelInterface = fs.LocalPeerState.KernelInterface
	pbFullStatus.LocalPeerState.Fqdn = fs.LocalPeerState.FQDN
	pbFullStatus.LocalPeerState.WgPort = int32(fs.LocalPeerState.WgPort)
	pbFullStatus.LocalPeerState.RosenpassPermissive = fs.RosenpassState.Permissive
	pbFullStatus.LocalPeerState.RosenpassEnabled = fs.RosenpassState.Enabled
	pbFullStatus.NumberOfForwardingRules = int32(fs.NumOfForwardingRules)
	pbFullStatus.LazyConnectionEnabled = fs.LazyConnectionEnabled

	pbFullStatus.LocalPeerState.Networks = maps.Keys(fs.LocalPeerState.Routes)

	for _, peerState := range fs.Peers {
		networks := maps.Keys(peerState.GetRoutes())

		pbPeerState := &proto.PeerState{
			IP:                         peerState.IP,
			Ipv6:                       peerState.IPv6,
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
			Networks:                   networks,
			Latency:                    durationpb.New(peerState.Latency),
			SshHostKey:                 peerState.SSHHostKey,
		}
		pbFullStatus.Peers = append(pbFullStatus.Peers, pbPeerState)
	}

	for _, relayState := range fs.Relays {
		pbRelayState := &proto.RelayState{
			URI:       relayState.URI,
			Available: relayState.Err == nil,
			Transport: relayState.Transport,
		}
		if err := relayState.Err; err != nil {
			pbRelayState.Error = err.Error()
		}
		pbFullStatus.Relays = append(pbFullStatus.Relays, pbRelayState)
	}

	for _, dnsState := range fs.NSGroupStates {
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

	pbFullStatus.Events = fs.Events

	return &pbFullStatus
}
