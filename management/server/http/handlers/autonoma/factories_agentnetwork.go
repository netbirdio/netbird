package autonoma

import (
	"context"
	"fmt"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"

	agentTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
)

// AgentNetworkSettingsInput bootstraps the account's LLM gateway. Without it
// the agent-network surface has no endpoint and no log collection, so a request
// through the gateway leaves usage rows but no access-log trail.
type AgentNetworkSettingsInput struct {
	AccountID string `json:"accountId"`
	// Endpoint is the hostname agents call. It is unique across every account,
	// so a recipe must make it per-run.
	Endpoint               string `json:"endpoint"`
	DisableLogCollection   bool   `json:"disableLogCollection,omitempty"`
	EnablePromptCollection bool   `json:"enablePromptCollection,omitempty"`
	AccessLogRetentionDays int    `json:"accessLogRetentionDays,omitempty"`
}

func (f *factories) agentNetworkSettingsFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *AgentNetworkSettingsInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			created, err := f.deps.AgentNetworkManager.CreateSettings(ctx, actor, &agentTypes.Settings{
				AccountID:              in.AccountID,
				EnableLogCollection:    !in.DisableLogCollection,
				EnablePromptCollection: in.EnablePromptCollection,
				AccessLogRetentionDays: orDefaultInt(in.AccessLogRetentionDays, 30),
			}, "", in.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("bootstrap the agent network on %q: %w", in.Endpoint, err)
			}

			return map[string]any{
				"id":        created.AccountID,
				"accountId": in.AccountID,
				"domain":    created.Domain,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AgentNetworkManager.DeleteSettings(ctx, accountID, owner)
		},
	)
}

// ProviderInput registers an upstream LLM vendor behind the gateway.
type ProviderInput struct {
	AccountID string `json:"accountId"`
	// GatewayID names the account's agent-network gateway. The provider is only
	// reachable through it, and the product refuses to delete a gateway that
	// still has providers - so referencing it is what puts the two in the right
	// order on the way up and on the way down.
	GatewayID string `json:"gatewayId,omitempty"`
	// ProviderID names the catalog entry, for example "openai" or "anthropic".
	ProviderID  string `json:"providerId"`
	Name        string `json:"name"`
	UpstreamURL string `json:"upstreamUrl"`
	// APIKey is required: a provider without one answers 401 on every request,
	// so the manager refuses to create it.
	APIKey   string `json:"apiKey"`
	Disabled bool   `json:"disabled,omitempty"`
}

func (f *factories) providerFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *ProviderInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}
			if in.GatewayID != "" {
				if _, err := lookupRef(fctx, "AgentNetworkSettings", in.GatewayID, "domain"); err != nil {
					return nil, err
				}
			}

			created, err := f.deps.AgentNetworkManager.CreateProvider(ctx, actor, &agentTypes.Provider{
				AccountID:   in.AccountID,
				ProviderID:  in.ProviderID,
				Name:        in.Name,
				UpstreamURL: in.UpstreamURL,
				APIKey:      in.APIKey,
				Enabled:     !in.Disabled,
			})
			if err != nil {
				return nil, fmt.Errorf("create agent network provider %q: %w", in.Name, err)
			}

			return map[string]any{"id": created.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AgentNetworkManager.DeleteProvider(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// GuardrailInput seeds a reusable guardrail set.
type GuardrailInput struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// AllowedModels restricts requests to these model ids; empty allows all.
	AllowedModels  []string `json:"allowedModels,omitempty"`
	CapturePrompts bool     `json:"capturePrompts,omitempty"`
	RedactPii      bool     `json:"redactPii,omitempty"`
}

func (f *factories) guardrailFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *GuardrailInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			guardrail := agentTypes.NewGuardrail(in.AccountID)
			guardrail.Name = in.Name
			guardrail.Description = in.Description
			guardrail.Checks = agentTypes.GuardrailChecks{
				ModelAllowlist: agentTypes.GuardrailModelAllowlist{
					Enabled: len(in.AllowedModels) > 0,
					Models:  strSlice(in.AllowedModels),
				},
				PromptCapture: agentTypes.GuardrailPromptCapture{
					Enabled:   in.CapturePrompts,
					RedactPii: in.RedactPii,
				},
			}

			created, err := f.deps.AgentNetworkManager.CreateGuardrail(ctx, actor, guardrail)
			if err != nil {
				return nil, fmt.Errorf("create guardrail %q: %w", in.Name, err)
			}

			return map[string]any{"id": created.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AgentNetworkManager.DeleteGuardrail(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// AccountBudgetRuleInput caps agent-network spend for a set of groups or users.
type AccountBudgetRuleInput struct {
	AccountID    string   `json:"accountId"`
	Name         string   `json:"name"`
	Disabled     bool     `json:"disabled,omitempty"`
	TargetGroups []string `json:"targetGroups,omitempty"`
	TargetUsers  []string `json:"targetUsers,omitempty"`
	// TokenCap and BudgetCapUsd are evaluated over a rolling window rather than
	// against a fixed date, so they need no offset. WindowSeconds is at least 60.
	TokenCap      int64   `json:"tokenCap,omitempty"`
	BudgetCapUsd  float64 `json:"budgetCapUsd,omitempty"`
	WindowSeconds int64   `json:"windowSeconds,omitempty"`
}

func (f *factories) budgetRuleFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *AccountBudgetRuleInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			window := in.WindowSeconds
			if window == 0 {
				window = 86400
			}

			rule := agentTypes.NewAccountBudgetRule(in.AccountID)
			rule.Name = in.Name
			rule.Enabled = !in.Disabled
			rule.TargetGroups = strSlice(in.TargetGroups)
			rule.TargetUsers = strSlice(in.TargetUsers)

			// A cap of zero means uncapped, so the cap has to land on the
			// dimension the rule actually targets: a user-targeted rule with
			// only a group cap set reads as "no limit" and silently lets every
			// request through. A rule that names neither is account-wide and
			// has to cap both, because a caller in no group would otherwise
			// escape it.
			capGroups := len(rule.TargetGroups) > 0 || len(rule.TargetUsers) == 0
			capUsers := len(rule.TargetUsers) > 0 || len(rule.TargetGroups) == 0

			tokens := agentTypes.PolicyTokenLimit{
				Enabled:       in.TokenCap > 0,
				WindowSeconds: window,
			}
			budget := agentTypes.PolicyBudgetLimit{
				Enabled:       in.BudgetCapUsd > 0,
				WindowSeconds: window,
			}
			if capGroups {
				tokens.GroupCap = in.TokenCap
				budget.GroupCapUsd = in.BudgetCapUsd
			}
			if capUsers {
				tokens.UserCap = in.TokenCap
				budget.UserCapUsd = in.BudgetCapUsd
			}
			rule.Limits = agentTypes.PolicyLimits{TokenLimit: tokens, BudgetLimit: budget}

			created, err := f.deps.AgentNetworkManager.CreateBudgetRule(ctx, actor, rule)
			if err != nil {
				return nil, fmt.Errorf("create budget rule %q: %w", in.Name, err)
			}

			return map[string]any{"id": created.ID, "accountId": in.AccountID, "name": in.Name}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.AgentNetworkManager.DeleteBudgetRule(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// ConsumptionInput ticks the gateway's spend counter for one identity.
//
// The counter is bucketed into a window aligned on the current time, so the row
// lands in the window the run is in - which is why the recipe carries a window
// length and token counts rather than a window start.
type ConsumptionInput struct {
	AccountID string `json:"accountId"`
	// DimensionKind is "user" or "group"; DimensionID is that user or group id.
	DimensionKind string  `json:"dimensionKind"`
	DimensionID   string  `json:"dimensionId"`
	WindowSeconds int64   `json:"windowSeconds,omitempty"`
	TokensInput   int64   `json:"tokensInput,omitempty"`
	TokensOutput  int64   `json:"tokensOutput,omitempty"`
	CostUSD       float64 `json:"costUsd,omitempty"`
}

func (f *factories) consumptionFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *ConsumptionInput, _ sdk.FactoryContext) (map[string]any, error) {
			window := in.WindowSeconds
			if window == 0 {
				window = 86400
			}
			kind := agentTypes.ConsumptionDimension(orDefaultStr(in.DimensionKind, string(agentTypes.DimensionUser)))
			// The column is part of the row's primary key and the readers switch
			// on it, so a value outside the two the product knows is a row
			// nothing can interpret.
			if kind != agentTypes.DimensionUser && kind != agentTypes.DimensionGroup {
				return nil, fmt.Errorf("dimensionKind must be %q or %q, got %q",
					agentTypes.DimensionUser, agentTypes.DimensionGroup, kind)
			}

			if err := f.deps.AgentNetworkManager.RecordConsumption(ctx, in.AccountID, kind, in.DimensionID,
				window, in.TokensInput, in.TokensOutput, in.CostUSD); err != nil {
				return nil, fmt.Errorf("record agent network consumption: %w", err)
			}

			// The row's identity is its composite key, so the id echoes it back
			// for teardown rather than inventing a surrogate.
			windowStart := agentTypes.WindowStart(nowUTC(), window)
			return map[string]any{
				"id":             fmt.Sprintf("%s/%s/%s/%d", in.AccountID, kind, in.DimensionID, window),
				"accountId":      in.AccountID,
				"dimensionKind":  string(kind),
				"dimensionId":    in.DimensionID,
				"windowSeconds":  window,
				"windowStartUtc": windowStart.Format(timeLayout),
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			window, _ := record["windowSeconds"].(float64)
			if window == 0 {
				if raw, ok := record["windowSeconds"].(int64); ok {
					window = float64(raw)
				}
			}
			windowStart, err := parseTime(str(record, "windowStartUtc"))
			if err != nil {
				return err
			}
			return f.cleaner.DeleteAgentNetworkConsumptionForTestData(ctx, str(record, "accountId"),
				agentTypes.ConsumptionDimension(str(record, "dimensionKind")), str(record, "dimensionId"),
				int64(window), windowStart)
		},
	)
}
