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
// lower-case daemon state ("ok", "no_user", "not_enabled", "user_blocked",
// "management_unsupported"). Times are RFC 3339, empty when unset.
type AgentNetworkInfo struct {
	State        string                 `json:"state"`
	UserEmail    string                 `json:"userEmail"`
	Endpoint     string                 `json:"endpoint"`
	LoginExpired bool                   `json:"loginExpired"`
	ComputedAt   string                 `json:"computedAt"`
	Providers    []AgentNetworkProvider `json:"providers"`
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
	ExhaustedReason  string              `json:"exhaustedReason"`
	Limits           []AgentNetworkLimit `json:"limits"`
}

// AgentNetworkLimit is one cap that binds the user. Source is "policy" or
// "account_rule", Unit "tokens" or "usd", Scope "user" or "group".
type AgentNetworkLimit struct {
	Source        string  `json:"source"`
	SourceID      string  `json:"sourceId"`
	SourceName    string  `json:"sourceName"`
	Unit          string  `json:"unit"`
	Scope         string  `json:"scope"`
	GroupID       string  `json:"groupId"`
	GroupName     string  `json:"groupName"`
	Cap           float64 `json:"cap"`
	Used          float64 `json:"used"`
	WindowSeconds int64   `json:"windowSeconds"`
	WindowStart   string  `json:"windowStart"`
	ResetsAt      string  `json:"resetsAt"`
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
		State:        strings.ToLower(resp.GetState().String()),
		UserEmail:    resp.GetUserEmail(),
		Endpoint:     resp.GetEndpoint(),
		LoginExpired: resp.GetLoginExpired(),
		ComputedAt:   formatTimestamp(resp.GetComputedAt()),
		Providers:    make([]AgentNetworkProvider, 0, len(resp.GetProviders())),
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
			ExhaustedReason:  p.GetExhaustedReason(),
			Limits:           make([]AgentNetworkLimit, 0, len(p.GetLimits())),
		}
		for _, l := range p.GetLimits() {
			provider.Limits = append(provider.Limits, AgentNetworkLimit{
				Source:        strings.ToLower(l.GetSource().String()),
				SourceID:      l.GetSourceId(),
				SourceName:    l.GetSourceName(),
				Unit:          strings.ToLower(l.GetUnit().String()),
				Scope:         strings.ToLower(l.GetScope().String()),
				GroupID:       l.GetGroupId(),
				GroupName:     l.GetGroupName(),
				Cap:           l.GetCap(),
				Used:          l.GetUsed(),
				WindowSeconds: l.GetWindowSeconds(),
				WindowStart:   formatTimestamp(l.GetWindowStart()),
				ResetsAt:      formatTimestamp(l.GetResetsAt()),
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
