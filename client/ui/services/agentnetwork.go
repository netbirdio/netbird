//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

// AgentNetworkInfo is what Agent Networks offers this peer. State is the
// lower-case daemon state ("ok", "not_enabled", "user_blocked",
// "management_unsupported"). Times are RFC 3339, empty when unset.
type AgentNetworkInfo struct {
	State     string                 `json:"state"`
	Endpoint  string                 `json:"endpoint"`
	Providers []AgentNetworkProvider `json:"providers"`
}

// AgentNetworkProvider is one provider the user may call, with their allowance.
type AgentNetworkProvider struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	CatalogID        string              `json:"catalogId"`
	APIFlavor        string              `json:"apiFlavor"`
	AllModelsAllowed bool                `json:"allModelsAllowed"`
	Models           []string            `json:"models"`
	Unlimited        bool                `json:"unlimited"`
	Exhausted        bool                `json:"exhausted"`
	Limits           []AgentNetworkLimit `json:"limits"`
}

// AgentNetworkLimit is one cap that binds the user. Unit is "tokens" or "usd".
type AgentNetworkLimit struct {
	Unit     string  `json:"unit"`
	Cap      float64 `json:"cap"`
	Used     float64 `json:"used"`
	ResetsAt string  `json:"resetsAt"`
}

// AgentNetwork is the Wails-facing Agent Networks service.
type AgentNetwork struct {
	conn DaemonConn
}

// NewAgentNetwork returns the Agent Networks service.
func NewAgentNetwork(conn DaemonConn) *AgentNetwork {
	return &AgentNetwork{conn: conn}
}

// Info asks the daemon what Agent Networks offers this peer.
func (s *AgentNetwork) Info(ctx context.Context) (AgentNetworkInfo, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return AgentNetworkInfo{}, err
	}
	resp, err := cli.GetAgentNetworkInfo(ctx, &proto.GetAgentNetworkInfoRequest{})
	if err != nil {
		return AgentNetworkInfo{}, err
	}
	return agentNetworkInfoFromProto(resp), nil
}

func agentNetworkInfoFromProto(resp *proto.GetAgentNetworkInfoResponse) AgentNetworkInfo {
	out := AgentNetworkInfo{
		State:     strings.ToLower(resp.GetState().String()),
		Endpoint:  resp.GetEndpoint(),
		Providers: make([]AgentNetworkProvider, 0, len(resp.GetProviders())),
	}
	for _, p := range resp.GetProviders() {
		provider := AgentNetworkProvider{
			ID:               p.GetId(),
			Name:             p.GetName(),
			CatalogID:        p.GetCatalogId(),
			APIFlavor:        p.GetApiFlavor(),
			AllModelsAllowed: p.GetAllModelsAllowed(),
			Models:           append([]string{}, p.GetModels()...),
			Unlimited:        p.GetUnlimited(),
			Exhausted:        p.GetExhausted(),
			Limits:           make([]AgentNetworkLimit, 0, len(p.GetLimits())),
		}
		for _, l := range p.GetLimits() {
			provider.Limits = append(provider.Limits, AgentNetworkLimit{
				Unit:     strings.ToLower(l.GetUnit().String()),
				Cap:      l.GetCap(),
				Used:     l.GetUsed(),
				ResetsAt: formatTimestamp(l.GetResetsAt()),
			})
		}
		out.Providers = append(out.Providers, provider)
	}
	return out
}

func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().Format(time.RFC3339)
}
