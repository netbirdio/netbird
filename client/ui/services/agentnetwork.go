//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// AgentNetworkInfo is what Agent Networks offers this peer. State is the
// lower-case daemon state ("ok", "no_user", "not_enabled", "user_blocked",
// "management_unsupported"). Times are RFC 3339, empty when unset.
type AgentNetworkInfo struct {
	State string `json:"state"`
	// UserEmail is the email the last SSO login stored on the active profile,
	// empty when there is none.
	UserEmail string                 `json:"userEmail"`
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

// AgentNetworkLimit is one cap that binds the user. Source is "policy" or
// "account_rule", Unit "tokens" or "usd", Scope "user" or "group".
type AgentNetworkLimit struct {
	Source     string  `json:"source"`
	SourceID   string  `json:"sourceId"`
	SourceName string  `json:"sourceName"`
	Unit       string  `json:"unit"`
	Scope      string  `json:"scope"`
	GroupID    string  `json:"groupId"`
	GroupName  string  `json:"groupName"`
	Cap        float64 `json:"cap"`
	Used       float64 `json:"used"`
	ResetsAt   string  `json:"resetsAt"`
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
	info := agentNetworkInfoFromProto(resp)
	info.UserEmail = activeProfileEmail(ctx, cli)
	return info, nil
}

// activeProfileEmail reads the email from the active profile's state file.
// The daemon names the active profile; the state file is user-owned, so it
// is read here rather than by the daemon. Empty when it cannot be read.
func activeProfileEmail(ctx context.Context, cli proto.DaemonServiceClient) string {
	active, err := cli.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		log.Debugf("failed to get active profile: %v", err)
		return ""
	}
	state, err := profilemanager.NewProfileManager().GetProfileState(profilemanager.ID(active.GetId()))
	if err != nil {
		log.Debugf("failed to get profile state: %v", err)
		return ""
	}
	return state.Email
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
				Source:     strings.ToLower(l.GetSource().String()),
				SourceID:   l.GetSourceId(),
				SourceName: l.GetSourceName(),
				Unit:       strings.ToLower(l.GetUnit().String()),
				Scope:      strings.ToLower(l.GetScope().String()),
				GroupID:    l.GetGroupId(),
				GroupName:  l.GetGroupName(),
				Cap:        l.GetCap(),
				Used:       l.GetUsed(),
				ResetsAt:   formatTimestamp(l.GetResetsAt()),
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
