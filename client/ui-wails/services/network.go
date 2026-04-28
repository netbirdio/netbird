//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// Network is one routed network the daemon offers to the client.
type Network struct {
	ID          string              `json:"id"`
	Range       string              `json:"range"`
	Selected    bool                `json:"selected"`
	Domains     []string            `json:"domains"`
	ResolvedIPs map[string][]string `json:"resolvedIps"`
}

// SelectNetworksParams selects which networks to enable / disable.
// All means "every available network" (used by Select-All / Deselect-All buttons);
// Append means "leave the existing selection in place and merge these IDs in".
type SelectNetworksParams struct {
	NetworkIDs []string `json:"networkIds"`
	Append     bool     `json:"append"`
	All        bool     `json:"all"`
}

// Networks groups the daemon RPCs that read and toggle routed networks.
type Networks struct {
	conn DaemonConn
}

func NewNetworks(conn DaemonConn) *Networks {
	return &Networks{conn: conn}
}

func (s *Networks) List(ctx context.Context) ([]Network, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return nil, err
	}
	resp, err := cli.ListNetworks(ctx, &proto.ListNetworksRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]Network, 0, len(resp.GetRoutes()))
	for _, n := range resp.GetRoutes() {
		out = append(out, networkFromProto(n))
	}
	return out, nil
}

func (s *Networks) Select(ctx context.Context, p SelectNetworksParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.SelectNetworks(ctx, &proto.SelectNetworksRequest{
		NetworkIDs: p.NetworkIDs,
		Append:     p.Append,
		All:        p.All,
	})
	return err
}

func (s *Networks) Deselect(ctx context.Context, p SelectNetworksParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.DeselectNetworks(ctx, &proto.SelectNetworksRequest{
		NetworkIDs: p.NetworkIDs,
		Append:     p.Append,
		All:        p.All,
	})
	return err
}

func networkFromProto(n *proto.Network) Network {
	resolved := make(map[string][]string, len(n.GetResolvedIPs()))
	for k, v := range n.GetResolvedIPs() {
		resolved[k] = append([]string{}, v.GetIps()...)
	}
	return Network{
		ID:          n.GetID(),
		Range:       n.GetRange(),
		Selected:    n.GetSelected(),
		Domains:     append([]string{}, n.GetDomains()...),
		ResolvedIPs: resolved,
	}
}
