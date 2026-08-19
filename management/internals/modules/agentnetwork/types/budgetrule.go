package types

import (
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// AccountBudgetRule is an account-level, limit-only rule bound to groups
// and/or users. It mirrors the policy budget experience without any routing:
// it carries the same cap shape as a policy (PolicyLimits) but never selects a
// provider. Rules apply across policies as an always-on ceiling — every
// applicable rule binds (min-wins), so a rule can only tighten a caller's
// effective limit, never loosen it.
//
// TargetGroups matches when it intersects the caller's groups; TargetUsers
// binds a specific user directly. Empty TargetGroups and TargetUsers means the
// rule applies to every caller (the account-wide default).
type AccountBudgetRule struct {
	ID           string `gorm:"primaryKey"`
	AccountID    string `gorm:"index"`
	Name         string
	Enabled      bool
	TargetGroups []string     `gorm:"serializer:json;column:target_groups"`
	TargetUsers  []string     `gorm:"serializer:json;column:target_users"`
	Limits       PolicyLimits `gorm:"serializer:json;column:limits"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName puts budget rules in their own table.
func (AccountBudgetRule) TableName() string { return "agent_network_budget_rules" }

// NewAccountBudgetRule returns a new rule with a freshly minted ID.
func NewAccountBudgetRule(accountID string) *AccountBudgetRule {
	now := time.Now().UTC()
	return &AccountBudgetRule{
		ID:        "ainbud_" + xid.New().String(),
		AccountID: accountID,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// Copy returns a deep copy of the rule, including its target slices.
func (r *AccountBudgetRule) Copy() *AccountBudgetRule {
	c := *r
	c.TargetGroups = append([]string(nil), r.TargetGroups...)
	c.TargetUsers = append([]string(nil), r.TargetUsers...)
	return &c
}

// EventMeta renders the rule for the activity log.
func (r *AccountBudgetRule) EventMeta() map[string]any {
	return map[string]any{
		"name":    r.Name,
		"enabled": r.Enabled,
	}
}

// FromAPIRequest applies the request payload onto the receiver.
func (r *AccountBudgetRule) FromAPIRequest(req *api.AgentNetworkBudgetRuleRequest) {
	r.Name = req.Name
	if req.Enabled != nil {
		r.Enabled = *req.Enabled
	}
	if req.TargetGroups != nil {
		r.TargetGroups = append([]string(nil), (*req.TargetGroups)...)
	} else {
		r.TargetGroups = []string{}
	}
	if req.TargetUsers != nil {
		r.TargetUsers = append([]string(nil), (*req.TargetUsers)...)
	} else {
		r.TargetUsers = []string{}
	}
	r.Limits = limitsFromAPI(req.Limits)
}

// ToAPIResponse renders the rule as the API representation.
func (r *AccountBudgetRule) ToAPIResponse() *api.AgentNetworkBudgetRule {
	groups := r.TargetGroups
	if groups == nil {
		groups = []string{}
	}
	users := r.TargetUsers
	if users == nil {
		users = []string{}
	}
	created := r.CreatedAt
	updated := r.UpdatedAt
	return &api.AgentNetworkBudgetRule{
		Id:           r.ID,
		Name:         r.Name,
		Enabled:      r.Enabled,
		TargetGroups: groups,
		TargetUsers:  users,
		Limits:       limitsToAPI(r.Limits),
		CreatedAt:    &created,
		UpdatedAt:    &updated,
	}
}
