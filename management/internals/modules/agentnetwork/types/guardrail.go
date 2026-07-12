package types

import (
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// GuardrailChecks is the configurable parameter set persisted with each
// guardrail. Stored as a JSON blob to keep the table flat.
type GuardrailChecks struct {
	ModelAllowlist GuardrailModelAllowlist `json:"model_allowlist"`
	PromptCapture  GuardrailPromptCapture  `json:"prompt_capture"`
}

type GuardrailModelAllowlist struct {
	Enabled bool     `json:"enabled"`
	Models  []string `json:"models"`
}

type GuardrailPromptCapture struct {
	Enabled   bool `json:"enabled"`
	RedactPii bool `json:"redact_pii"`
}

// Guardrail is an Agent Network reusable guardrail set persisted per account.
type Guardrail struct {
	ID          string `gorm:"primaryKey"`
	AccountID   string `gorm:"index"`
	Name        string
	Description string
	Checks      GuardrailChecks `gorm:"serializer:json"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TableName uses an explicit name so guardrail rows live in their own
// table.
func (Guardrail) TableName() string { return "agent_network_guardrails" }

// NewGuardrail returns a new Guardrail with a freshly minted ID.
func NewGuardrail(accountID string) *Guardrail {
	now := time.Now().UTC()
	return &Guardrail{
		ID:        "ainguard_" + xid.New().String(),
		AccountID: accountID,
		Checks:    GuardrailChecks{ModelAllowlist: GuardrailModelAllowlist{Models: []string{}}},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// FromAPIRequest applies the request payload onto the receiver.
func (g *Guardrail) FromAPIRequest(req *api.AgentNetworkGuardrailRequest) {
	g.Name = req.Name
	if req.Description != nil {
		g.Description = *req.Description
	}
	g.Checks = checksFromAPI(req.Checks)
}

// ToAPIResponse renders the guardrail as the API representation.
func (g *Guardrail) ToAPIResponse() *api.AgentNetworkGuardrail {
	created := g.CreatedAt
	updated := g.UpdatedAt
	return &api.AgentNetworkGuardrail{
		Id:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		Checks:      checksToAPI(g.Checks),
		CreatedAt:   &created,
		UpdatedAt:   &updated,
	}
}

// Copy returns a deep copy of the guardrail.
func (g *Guardrail) Copy() *Guardrail {
	clone := *g
	if g.Checks.ModelAllowlist.Models != nil {
		clone.Checks.ModelAllowlist.Models = append([]string(nil), g.Checks.ModelAllowlist.Models...)
	}
	return &clone
}

// EventMeta is the audit-log payload for activity events.
func (g *Guardrail) EventMeta() map[string]any {
	return map[string]any{"name": g.Name}
}

func checksFromAPI(c api.AgentNetworkGuardrailChecks) GuardrailChecks {
	models := append([]string(nil), c.ModelAllowlist.Models...)
	if models == nil {
		models = []string{}
	}
	return GuardrailChecks{
		ModelAllowlist: GuardrailModelAllowlist{
			Enabled: c.ModelAllowlist.Enabled,
			Models:  models,
		},
		PromptCapture: GuardrailPromptCapture{
			Enabled:   c.PromptCapture.Enabled,
			RedactPii: c.PromptCapture.RedactPii,
		},
	}
}

func checksToAPI(c GuardrailChecks) api.AgentNetworkGuardrailChecks {
	models := c.ModelAllowlist.Models
	if models == nil {
		models = []string{}
	}
	out := api.AgentNetworkGuardrailChecks{}
	out.ModelAllowlist.Enabled = c.ModelAllowlist.Enabled
	out.ModelAllowlist.Models = models
	out.PromptCapture.Enabled = c.PromptCapture.Enabled
	out.PromptCapture.RedactPii = c.PromptCapture.RedactPii
	return out
}
