//go:build !(linux && 386)

package services

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// PeersService exposes peer listing operations to the Wails frontend.
type PeersService struct {
	grpcClient GRPCClientIface
}

// NewPeersService creates a new PeersService.
func NewPeersService(g GRPCClientIface) *PeersService {
	return &PeersService{grpcClient: g}
}

// GetPeers returns the list of all peers with their status information.
func (s *PeersService) GetPeers() ([]PeerInfo, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		log.Debugf("GetPeers: failed to get gRPC client: %v", err)
		return nil, fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		log.Warnf("GetPeers: status RPC failed: %v", err)
		return nil, fmt.Errorf("status rpc: %w", err)
	}

	if resp.FullStatus == nil {
		log.Debugf("GetPeers: fullStatus is nil")
		return []PeerInfo{}, nil
	}

	peers := resp.FullStatus.GetPeers()
	log.Debugf("GetPeers: got %d peers from daemon", len(peers))

	result := make([]PeerInfo, 0, len(peers))
	for _, p := range peers {
		info := PeerInfo{
			IP:               p.GetIP(),
			PubKey:           p.GetPubKey(),
			Fqdn:             p.GetFqdn(),
			ConnStatus:       p.GetConnStatus(),
			Relayed:          p.GetRelayed(),
			RelayAddress:     p.GetRelayAddress(),
			BytesRx:          p.GetBytesRx(),
			BytesTx:          p.GetBytesTx(),
			RosenpassEnabled: p.GetRosenpassEnabled(),
			Networks:         p.GetNetworks(),
			LocalIceType:     p.GetLocalIceCandidateType(),
			RemoteIceType:    p.GetRemoteIceCandidateType(),
			LocalEndpoint:    p.GetLocalIceCandidateEndpoint(),
			RemoteEndpoint:   p.GetRemoteIceCandidateEndpoint(),
		}

		if lat := p.GetLatency(); lat != nil {
			info.LatencyMs = float64(lat.Seconds)*1000 + float64(lat.Nanos)/1e6
		}

		if ts := p.GetLastWireguardHandshake(); ts != nil {
			info.LastHandshake = ts.AsTime().Format(time.RFC3339)
		}

		if ts := p.GetConnStatusUpdate(); ts != nil {
			info.ConnStatusUpdate = ts.AsTime().Format(time.RFC3339)
		}

		result = append(result, info)
	}

	return result, nil
}

// PeerInfo holds simplified peer information for the frontend.
type PeerInfo struct {
	IP               string   `json:"ip"`
	PubKey           string   `json:"pubKey"`
	Fqdn             string   `json:"fqdn"`
	ConnStatus       string   `json:"connStatus"`
	ConnStatusUpdate string   `json:"connStatusUpdate"`
	Relayed          bool     `json:"relayed"`
	RelayAddress     string   `json:"relayAddress"`
	LatencyMs        float64  `json:"latencyMs"`
	BytesRx          int64    `json:"bytesRx"`
	BytesTx          int64    `json:"bytesTx"`
	RosenpassEnabled bool     `json:"rosenpassEnabled"`
	Networks         []string `json:"networks"`
	LastHandshake    string   `json:"lastHandshake"`
	LocalIceType     string   `json:"localIceType"`
	RemoteIceType    string   `json:"remoteIceType"`
	LocalEndpoint    string   `json:"localEndpoint"`
	RemoteEndpoint   string   `json:"remoteEndpoint"`
}
