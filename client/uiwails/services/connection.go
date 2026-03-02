//go:build !(linux && 386)

package services

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// ConnectionService exposes connect/disconnect/status operations to the Wails frontend.
type ConnectionService struct {
	grpcClient GRPCClientIface
}

// NewConnectionService creates a new ConnectionService.
func NewConnectionService(g GRPCClientIface) *ConnectionService {
	return &ConnectionService{grpcClient: g}
}

// GetStatus returns the current daemon status.
func (s *ConnectionService) GetStatus() (*StatusInfo, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		log.Debugf("GetStatus: failed to get gRPC client: %v", err)
		return nil, fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		log.Warnf("GetStatus: status RPC failed: %v", err)
		return nil, fmt.Errorf("status rpc: %w", err)
	}

	log.Debugf("GetStatus: daemon responded status=%q daemonVersion=%q fullStatus=%v",
		resp.Status, resp.DaemonVersion, resp.FullStatus != nil)

	info := &StatusInfo{
		Status: resp.Status,
	}

	if resp.FullStatus != nil && resp.FullStatus.LocalPeerState != nil {
		lp := resp.FullStatus.LocalPeerState
		info.IP = lp.GetIP()
		info.PublicKey = lp.GetPubKey()
		info.Fqdn = lp.GetFqdn()
		log.Debugf("GetStatus: localPeer ip=%q fqdn=%q pubKey=%q", info.IP, info.Fqdn, info.PublicKey)
	} else if resp.FullStatus == nil {
		log.Warnf("GetStatus: fullStatus is nil — daemon may not support full status or request flag was not set")
	} else {
		log.Debugf("GetStatus: fullStatus present but LocalPeerState is nil")
	}

	if resp.FullStatus != nil {
		info.ConnectedPeers = len(resp.FullStatus.GetPeers())
		log.Debugf("GetStatus: connectedPeers=%d", info.ConnectedPeers)
	}

	return info, nil
}

// Connect sends an Up request to the daemon.
func (s *ConnectionService) Connect() error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := conn.Up(ctx, &proto.UpRequest{}); err != nil {
		log.Errorf("Up rpc failed: %v", err)
		return fmt.Errorf("connect: %w", err)
	}

	return nil
}

// Disconnect sends a Down request to the daemon.
func (s *ConnectionService) Disconnect() error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := conn.Down(ctx, &proto.DownRequest{}); err != nil {
		log.Errorf("Down rpc failed: %v", err)
		return fmt.Errorf("disconnect: %w", err)
	}

	return nil
}

// StatusInfo holds simplified status information for the frontend.
type StatusInfo struct {
	Status         string `json:"status"`
	IP             string `json:"ip"`
	PublicKey      string `json:"publicKey"`
	Fqdn           string `json:"fqdn"`
	ConnectedPeers int    `json:"connectedPeers"`
}
