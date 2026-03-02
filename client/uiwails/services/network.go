//go:build !(linux && 386)

package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// NetworkService exposes network/route management to the Wails frontend.
type NetworkService struct {
	grpcClient GRPCClientIface
}

// NewNetworkService creates a new NetworkService.
func NewNetworkService(g GRPCClientIface) *NetworkService {
	return &NetworkService{grpcClient: g}
}

// NetworkInfo is a serializable view of a single network/route.
type NetworkInfo struct {
	ID          string              `json:"id"`
	Range       string              `json:"range"`
	Domains     []string            `json:"domains"`
	Selected    bool                `json:"selected"`
	ResolvedIPs map[string][]string `json:"resolvedIPs"`
}

// ListNetworks returns all networks from the daemon.
func (s *NetworkService) ListNetworks() ([]NetworkInfo, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.ListNetworks(ctx, &proto.ListNetworksRequest{})
	if err != nil {
		return nil, fmt.Errorf("list networks rpc: %w", err)
	}

	routes := make([]NetworkInfo, 0, len(resp.Routes))
	for _, r := range resp.Routes {
		info := NetworkInfo{
			ID:       r.GetID(),
			Range:    r.GetRange(),
			Domains:  r.GetDomains(),
			Selected: r.GetSelected(),
		}
		if resolvedMap := r.GetResolvedIPs(); resolvedMap != nil {
			info.ResolvedIPs = make(map[string][]string)
			for domain, ipList := range resolvedMap {
				info.ResolvedIPs[domain] = ipList.GetIps()
			}
		}
		routes = append(routes, info)
	}

	sort.Slice(routes, func(i, j int) bool {
		return strings.ToLower(routes[i].ID) < strings.ToLower(routes[j].ID)
	})

	return routes, nil
}

// ListOverlappingNetworks returns only networks with overlapping ranges.
func (s *NetworkService) ListOverlappingNetworks() ([]NetworkInfo, error) {
	all, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}

	existingRange := make(map[string][]NetworkInfo)
	for _, r := range all {
		if len(r.Domains) > 0 {
			continue
		}
		existingRange[r.Range] = append(existingRange[r.Range], r)
	}

	var result []NetworkInfo
	for _, group := range existingRange {
		if len(group) > 1 {
			result = append(result, group...)
		}
	}
	return result, nil
}

// ListExitNodes returns networks with range 0.0.0.0/0 (exit nodes).
func (s *NetworkService) ListExitNodes() ([]NetworkInfo, error) {
	all, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}

	var result []NetworkInfo
	for _, r := range all {
		if r.Range == "0.0.0.0/0" {
			result = append(result, r)
		}
	}
	return result, nil
}

// SelectNetwork selects a single network by ID.
func (s *NetworkService) SelectNetwork(id string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &proto.SelectNetworksRequest{
		NetworkIDs: []string{id},
		Append:     true,
	}
	if _, err := conn.SelectNetworks(ctx, req); err != nil {
		log.Errorf("SelectNetworks rpc failed: %v", err)
		return fmt.Errorf("select network: %w", err)
	}
	return nil
}

// DeselectNetwork deselects a single network by ID.
func (s *NetworkService) DeselectNetwork(id string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &proto.SelectNetworksRequest{
		NetworkIDs: []string{id},
	}
	if _, err := conn.DeselectNetworks(ctx, req); err != nil {
		log.Errorf("DeselectNetworks rpc failed: %v", err)
		return fmt.Errorf("deselect network: %w", err)
	}
	return nil
}

// SelectAllNetworks selects all networks.
func (s *NetworkService) SelectAllNetworks() error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &proto.SelectNetworksRequest{All: true}
	if _, err := conn.SelectNetworks(ctx, req); err != nil {
		return fmt.Errorf("select all networks: %w", err)
	}
	return nil
}

// DeselectAllNetworks deselects all networks.
func (s *NetworkService) DeselectAllNetworks() error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &proto.SelectNetworksRequest{All: true}
	if _, err := conn.DeselectNetworks(ctx, req); err != nil {
		return fmt.Errorf("deselect all networks: %w", err)
	}
	return nil
}

// SelectNetworks selects a list of networks by ID.
func (s *NetworkService) SelectNetworks(ids []string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &proto.SelectNetworksRequest{NetworkIDs: ids, Append: true}
	if _, err := conn.SelectNetworks(ctx, req); err != nil {
		return fmt.Errorf("select networks: %w", err)
	}
	return nil
}

// DeselectNetworks deselects a list of networks by ID.
func (s *NetworkService) DeselectNetworks(ids []string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &proto.SelectNetworksRequest{NetworkIDs: ids}
	if _, err := conn.DeselectNetworks(ctx, req); err != nil {
		return fmt.Errorf("deselect networks: %w", err)
	}
	return nil
}
