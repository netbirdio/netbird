package types

import (
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// Policy is an Agent Network policy persisted per account. A policy
// authorises members of SourceGroups to reach the listed
// DestinationProviderIDs under the attached GuardrailIDs and Limits.
//
// Token and budget limits live on the Policy itself (Limits field);
// guardrails carry only model allowlist and prompt capture.
type Policy struct {
	ID                     string `gorm:"primaryKey"`
	AccountID              string `gorm:"index"`
	Name                   string
	Description            string
	Enabled                bool
	SourceGroups           []string     `gorm:"serializer:json;column:source_groups"`
	DestinationProviderIDs []string     `gorm:"serializer:json;column:destination_provider_ids"`
	GuardrailIDs           []string     `gorm:"serializer:json;column:guardrail_ids"`
	Limits                 PolicyLimits `gorm:"serializer:json;column:limits"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// PolicyLimits aggregates the token and budget caps attached directly
// to a policy. Both halves are always present; their Enabled flags
// control whether the proxy enforces them.
type PolicyLimits struct {
	TokenLimit  PolicyTokenLimit  `json:"token_limit"`
	BudgetLimit PolicyBudgetLimit `json:"budget_limit"`
}

// PolicyTokenLimit is a token-count cap evaluated over an aligned
// window of WindowSeconds seconds. GroupCap is applied to each
// source group independently — every group in the policy's
// SourceGroups gets its own bucket of GroupCap tokens. UserCap
// applies independently to each individual user. A zero cap means
// uncapped. WindowSeconds must be at least 60 (one minute) when the
// limit is enabled.
type PolicyTokenLimit struct {
	Enabled       bool  `json:"enabled"`
	GroupCap      int64 `json:"group_cap"`
	UserCap       int64 `json:"user_cap"`
	WindowSeconds int64 `json:"window_seconds"`
}

// PolicyBudgetLimit is a USD spend cap evaluated over an aligned
// window of WindowSeconds seconds. GroupCapUsd is applied to each
// source group independently — every group in the policy's
// SourceGroups gets its own bucket of GroupCapUsd USD. UserCapUsd
// applies independently to each individual user. A zero cap means
// uncapped. WindowSeconds must be at least 60 (one minute) when the
// limit is enabled.
type PolicyBudgetLimit struct {
	Enabled       bool    `json:"enabled"`
	GroupCapUsd   float64 `json:"group_cap_usd"`
	UserCapUsd    float64 `json:"user_cap_usd"`
	WindowSeconds int64   `json:"window_seconds"`
}

// TableName forces a unique GORM table to avoid collision with the access
// control Policy type, which also resolves to "policies" by default.
func (Policy) TableName() string { return "agent_network_policies" }

// NewPolicy returns a new Policy with a freshly minted ID.
func NewPolicy(accountID string) *Policy {
	now := time.Now().UTC()
	return &Policy{
		ID:        "ainpol_" + xid.New().String(),
		AccountID: accountID,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// FromAPIRequest applies the request payload onto the receiver.
func (p *Policy) FromAPIRequest(req *api.AgentNetworkPolicyRequest) {
	p.Name = req.Name
	if req.Description != nil {
		p.Description = *req.Description
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	p.SourceGroups = append([]string(nil), req.SourceGroups...)
	p.DestinationProviderIDs = append([]string(nil), req.DestinationProviderIds...)
	if req.GuardrailIds != nil {
		p.GuardrailIDs = append([]string(nil), (*req.GuardrailIds)...)
	} else {
		p.GuardrailIDs = []string{}
	}
	if req.Limits != nil {
		p.Limits = limitsFromAPI(*req.Limits)
	} else {
		p.Limits = PolicyLimits{}
	}
}

// ToAPIResponse renders the policy as the API representation.
func (p *Policy) ToAPIResponse() *api.AgentNetworkPolicy {
	src := p.SourceGroups
	if src == nil {
		src = []string{}
	}
	dst := p.DestinationProviderIDs
	if dst == nil {
		dst = []string{}
	}
	guardrails := p.GuardrailIDs
	if guardrails == nil {
		guardrails = []string{}
	}
	created := p.CreatedAt
	updated := p.UpdatedAt
	return &api.AgentNetworkPolicy{
		Id:                     p.ID,
		Name:                   p.Name,
		Description:            p.Description,
		Enabled:                p.Enabled,
		SourceGroups:           src,
		DestinationProviderIds: dst,
		GuardrailIds:           guardrails,
		Limits:                 limitsToAPI(p.Limits),
		CreatedAt:              &created,
		UpdatedAt:              &updated,
	}
}

// Copy returns a deep copy of the policy.
func (p *Policy) Copy() *Policy {
	clone := *p
	if p.SourceGroups != nil {
		clone.SourceGroups = append([]string(nil), p.SourceGroups...)
	}
	if p.DestinationProviderIDs != nil {
		clone.DestinationProviderIDs = append([]string(nil), p.DestinationProviderIDs...)
	}
	if p.GuardrailIDs != nil {
		clone.GuardrailIDs = append([]string(nil), p.GuardrailIDs...)
	}
	return &clone
}

// EventMeta is the audit-log payload for activity events.
func (p *Policy) EventMeta() map[string]any {
	return map[string]any{
		"name":    p.Name,
		"enabled": p.Enabled,
	}
}

func limitsFromAPI(in api.AgentNetworkPolicyLimits) PolicyLimits {
	return PolicyLimits{
		TokenLimit: PolicyTokenLimit{
			Enabled:       in.TokenLimit.Enabled,
			GroupCap:      in.TokenLimit.GroupCap,
			UserCap:       in.TokenLimit.UserCap,
			WindowSeconds: in.TokenLimit.WindowSeconds,
		},
		BudgetLimit: PolicyBudgetLimit{
			Enabled:       in.BudgetLimit.Enabled,
			GroupCapUsd:   in.BudgetLimit.GroupCapUsd,
			UserCapUsd:    in.BudgetLimit.UserCapUsd,
			WindowSeconds: in.BudgetLimit.WindowSeconds,
		},
	}
}

func limitsToAPI(in PolicyLimits) api.AgentNetworkPolicyLimits {
	return api.AgentNetworkPolicyLimits{
		TokenLimit: api.AgentNetworkPolicyTokenLimit{
			Enabled:       in.TokenLimit.Enabled,
			GroupCap:      in.TokenLimit.GroupCap,
			UserCap:       in.TokenLimit.UserCap,
			WindowSeconds: in.TokenLimit.WindowSeconds,
		},
		BudgetLimit: api.AgentNetworkPolicyBudgetLimit{
			Enabled:       in.BudgetLimit.Enabled,
			GroupCapUsd:   in.BudgetLimit.GroupCapUsd,
			UserCapUsd:    in.BudgetLimit.UserCapUsd,
			WindowSeconds: in.BudgetLimit.WindowSeconds,
		},
	}
}
