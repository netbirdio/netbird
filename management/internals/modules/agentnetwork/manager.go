package agentnetwork

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/labelgen"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ensureSessionKeys mints an ed25519 session keypair on the provider
// when one is missing. Idempotent: skips when both fields are already
// populated (e.g. update or migrated rows). The keys are used by the
// synthesised reverse-proxy service to sign / verify session JWTs
// after a successful OIDC handshake.
func ensureSessionKeys(p *types.Provider) error {
	if p.SessionPrivateKey != "" && p.SessionPublicKey != "" {
		return nil
	}
	pair, err := sessionkey.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate provider session keys: %w", err)
	}
	p.SessionPrivateKey = pair.PrivateKey
	p.SessionPublicKey = pair.PublicKey
	return nil
}

// Manager governs the lifecycle of Agent Network providers and policies.
type Manager interface {
	GetAllProviders(ctx context.Context, accountID, userID string) ([]*types.Provider, error)
	GetProvider(ctx context.Context, accountID, userID, providerID string) (*types.Provider, error)
	CreateProvider(ctx context.Context, userID string, provider *types.Provider) (*types.Provider, error)
	UpdateProvider(ctx context.Context, userID string, provider *types.Provider) (*types.Provider, error)
	DeleteProvider(ctx context.Context, accountID, userID, providerID string) error

	GetAllPolicies(ctx context.Context, accountID, userID string) ([]*types.Policy, error)
	GetPolicy(ctx context.Context, accountID, userID, policyID string) (*types.Policy, error)
	CreatePolicy(ctx context.Context, userID string, policy *types.Policy) (*types.Policy, error)
	UpdatePolicy(ctx context.Context, userID string, policy *types.Policy) (*types.Policy, error)
	DeletePolicy(ctx context.Context, accountID, userID, policyID string) error

	GetAllGuardrails(ctx context.Context, accountID, userID string) ([]*types.Guardrail, error)
	GetGuardrail(ctx context.Context, accountID, userID, guardrailID string) (*types.Guardrail, error)
	CreateGuardrail(ctx context.Context, userID string, guardrail *types.Guardrail) (*types.Guardrail, error)
	UpdateGuardrail(ctx context.Context, userID string, guardrail *types.Guardrail) (*types.Guardrail, error)
	DeleteGuardrail(ctx context.Context, accountID, userID, guardrailID string) error

	GetAllBudgetRules(ctx context.Context, accountID, userID string) ([]*types.AccountBudgetRule, error)
	GetBudgetRule(ctx context.Context, accountID, userID, ruleID string) (*types.AccountBudgetRule, error)
	CreateBudgetRule(ctx context.Context, userID string, rule *types.AccountBudgetRule) (*types.AccountBudgetRule, error)
	UpdateBudgetRule(ctx context.Context, userID string, rule *types.AccountBudgetRule) (*types.AccountBudgetRule, error)
	DeleteBudgetRule(ctx context.Context, accountID, userID, ruleID string) error

	GetSettings(ctx context.Context, accountID, userID string) (*types.Settings, error)
	CreateSettings(ctx context.Context, userID string, settings *types.Settings, proxyAddress, endpoint string) (*types.Settings, error)
	UpdateSettings(ctx context.Context, userID string, settings *types.Settings) (*types.Settings, error)

	ListConsumption(ctx context.Context, accountID, userID string) ([]*types.Consumption, error)
	ListAccessLogs(ctx context.Context, accountID, userID string, filter types.AgentNetworkAccessLogFilter) ([]*types.AgentNetworkAccessLog, int64, error)
	ListAccessLogSessions(ctx context.Context, accountID, userID string, filter types.AgentNetworkAccessLogFilter) ([]*types.AgentNetworkAccessLogSession, int64, error)
	GetUsageOverview(ctx context.Context, accountID, userID string, filter types.AgentNetworkAccessLogFilter, granularity types.UsageGranularity) ([]*types.AgentNetworkUsageBucket, error)
	StartAccessLogCleanup(ctx context.Context, cleanupIntervalHours int)
	RecordConsumption(ctx context.Context, accountID string, kind types.ConsumptionDimension, dimID string, windowSeconds, tokensIn, tokensOut int64, costUSD float64) error
	RecordAccountBudgetUsage(ctx context.Context, accountID, userID string, groupIDs []string, tokensIn, tokensOut int64, costUSD float64) error
	RecordUsage(ctx context.Context, in RecordUsageInput) error
	SelectPolicyForRequest(ctx context.Context, in PolicySelectionInput) (*PolicySelectionResult, error)
}

// PolicySelectionInput is the per-request selection envelope. The
// proxy populates it from CapturedData (account, user, groups) plus
// the provider llm_router resolved and the model it extracted.
type PolicySelectionInput struct {
	AccountID  string
	UserID     string
	GroupIDs   []string
	ProviderID string
	// Model is the already-normalised upstream model id the proxy extracted
	// (parser strips Bedrock region/version, Vertex @version), so a
	// case-insensitive compare suffices. Empty = undetermined → not permitted
	// (fail closed).
	Model string
}

// PolicySelectionResult names the policy that "pays" for this request
// plus the deny envelope when every applicable policy has exhausted
// every cap. AttributionGroupID is the lowest group id (string sort)
// of caller_groups ∩ selected_policy.source_groups; empty when no
// group dimension applies. WindowSeconds is the chosen policy's
// effective window length in seconds (token_limit's wins when both
// halves are enabled with mismatched windows; budget_limit's
// otherwise; 0 when no caps are configured at all).
type PolicySelectionResult struct {
	Allow              bool
	SelectedPolicyID   string
	AttributionGroupID string
	WindowSeconds      int64
	DenyCode           string
	DenyReason         string
}

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	proxyController    proxy.Controller

	// reconcileCache holds the last set of synthesised proxy mappings
	// per account, each paired with the proxy that served it, so a change
	// of serving proxy can be diffed without re-deriving it.
	reconcileMu    sync.Mutex
	reconcileCache map[string]map[string]syntheticMapping

	// labelRngMu guards labelRng. PickUnique consumes math/rand.Source
	// state; concurrent provider creates would otherwise race.
	labelRngMu sync.Mutex
	labelRng   *rand.Rand
}

// NewManager constructs the persistent Agent Network manager. The
// manager persists provider/policy/guardrail configuration and, on
// every mutation, reconciles the in-memory synthesised reverse-proxy
// services with the proxy cluster via proxyController. Pass nil for
// proxyController to disable the reconcile push (useful in tests).
func NewManager(
	store store.Store,
	permissionsManager permissions.Manager,
	accountManager account.Manager,
	proxyController proxy.Controller,
) Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
		proxyController:    proxyController,
		reconcileCache:     make(map[string]map[string]syntheticMapping),
		labelRng:           rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (m *managerImpl) GetAllProviders(ctx context.Context, accountID, userID string) ([]*types.Provider, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetProvider(ctx context.Context, accountID, userID, providerID string) (*types.Provider, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, accountID, providerID)
}

// CreateProvider persists a new provider for the account. Providers have no
// settings side effects: the account's endpoint is bootstrapped separately and
// explicitly via CreateSettings, and every provider in the account routes
// through it.
func (m *managerImpl) CreateProvider(ctx context.Context, userID string, provider *types.Provider) (*types.Provider, error) {
	if err := m.requirePermission(ctx, provider.AccountID, userID, modules.AgentNetworkProviders, operations.Create); err != nil {
		return nil, err
	}

	// An empty api_key would silently produce a synthesised service
	// that 401s on every upstream request. Surface the misconfiguration
	// at create time instead.
	if strings.TrimSpace(provider.APIKey) == "" {
		return nil, status.Errorf(status.InvalidArgument, "api_key is required when creating an agent network provider")
	}

	if provider.ID == "" {
		fresh := types.NewProvider(provider.AccountID)
		provider.ID = fresh.ID
		provider.CreatedAt = fresh.CreatedAt
		provider.UpdatedAt = fresh.UpdatedAt
	}

	if err := ensureSessionKeys(provider); err != nil {
		return nil, err
	}

	if err := m.store.SaveAgentNetworkProvider(ctx, provider); err != nil {
		return nil, fmt.Errorf("save agent network provider: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, provider.ID, provider.AccountID, activity.AgentNetworkProviderCreated, provider.EventMeta())
	m.reconcile(ctx, provider.AccountID)

	return provider, nil
}

func (m *managerImpl) UpdateProvider(ctx context.Context, userID string, provider *types.Provider) (*types.Provider, error) {
	if err := m.requirePermission(ctx, provider.AccountID, userID, modules.AgentNetworkProviders, operations.Update); err != nil {
		return nil, err
	}

	existing, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthUpdate, provider.AccountID, provider.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent network provider: %w", err)
	}

	// Preserve the API key if the caller didn't rotate it. A
	// whitespace-only value is treated as "not rotated" rather than a
	// real key, but it must not silently overwrite a valid stored key.
	if provider.APIKey == "" {
		provider.APIKey = existing.APIKey
	} else if strings.TrimSpace(provider.APIKey) == "" {
		return nil, status.Errorf(status.InvalidArgument, "api_key must be non-blank when rotating an agent network provider")
	}
	// Always preserve the session keypair across updates so existing
	// session cookies stay valid. The keys are server-managed and
	// never surfaced through the API.
	provider.SessionPrivateKey = existing.SessionPrivateKey
	provider.SessionPublicKey = existing.SessionPublicKey
	if err := ensureSessionKeys(provider); err != nil {
		return nil, err
	}
	provider.CreatedAt = existing.CreatedAt
	provider.UpdatedAt = time.Now().UTC()

	if err := m.store.SaveAgentNetworkProvider(ctx, provider); err != nil {
		return nil, fmt.Errorf("save agent network provider: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, provider.ID, provider.AccountID, activity.AgentNetworkProviderUpdated, provider.EventMeta())
	m.reconcile(ctx, provider.AccountID)

	return provider, nil
}

func (m *managerImpl) DeleteProvider(ctx context.Context, accountID, userID, providerID string) error {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Delete); err != nil {
		return err
	}

	provider, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthUpdate, accountID, providerID)
	if err != nil {
		return fmt.Errorf("failed to get agent network provider: %w", err)
	}

	// Refuse to delete while any policy still references this provider.
	// The operator must detach it first.
	policies, err := m.store.GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("failed to get agent network policies: %w", err)
	}
	var blocking []string
	for _, p := range policies {
		if slices.Contains(p.DestinationProviderIDs, providerID) {
			blocking = append(blocking, p.Name)
		}
	}
	if len(blocking) > 0 {
		return status.Errorf(
			status.InvalidArgument,
			"provider is in use by %d %s (%s); detach it before deleting",
			len(blocking),
			pluralize(len(blocking), "policy", "policies"),
			strings.Join(blocking, ", "),
		)
	}

	if err := m.store.DeleteAgentNetworkProvider(ctx, accountID, providerID); err != nil {
		return fmt.Errorf("failed to delete agent network provider: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, providerID, accountID, activity.AgentNetworkProviderDeleted, provider.EventMeta())
	m.reconcile(ctx, accountID)

	return nil
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

func (m *managerImpl) GetAllPolicies(ctx context.Context, accountID, userID string) ([]*types.Policy, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkPolicies, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetPolicy(ctx context.Context, accountID, userID, policyID string) (*types.Policy, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkPolicies, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAgentNetworkPolicyByID(ctx, store.LockingStrengthNone, accountID, policyID)
}

func (m *managerImpl) CreatePolicy(ctx context.Context, userID string, policy *types.Policy) (*types.Policy, error) {
	if err := m.requirePermission(ctx, policy.AccountID, userID, modules.AgentNetworkPolicies, operations.Create); err != nil {
		return nil, err
	}

	if policy.ID == "" {
		fresh := types.NewPolicy(policy.AccountID)
		policy.ID = fresh.ID
		policy.CreatedAt = fresh.CreatedAt
		policy.UpdatedAt = fresh.UpdatedAt
	}

	if err := m.validateProviderRefs(ctx, policy.AccountID, policy.DestinationProviderIDs); err != nil {
		return nil, err
	}

	if err := m.store.SaveAgentNetworkPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to save agent network policy: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, policy.ID, policy.AccountID, activity.AgentNetworkPolicyCreated, policy.EventMeta())
	m.reconcile(ctx, policy.AccountID)

	return policy, nil
}

func (m *managerImpl) UpdatePolicy(ctx context.Context, userID string, policy *types.Policy) (*types.Policy, error) {
	if err := m.requirePermission(ctx, policy.AccountID, userID, modules.AgentNetworkPolicies, operations.Update); err != nil {
		return nil, err
	}

	existing, err := m.store.GetAgentNetworkPolicyByID(ctx, store.LockingStrengthUpdate, policy.AccountID, policy.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent network policy: %w", err)
	}

	if err := m.validateProviderRefs(ctx, policy.AccountID, policy.DestinationProviderIDs); err != nil {
		return nil, err
	}

	policy.CreatedAt = existing.CreatedAt
	policy.UpdatedAt = time.Now().UTC()

	if err := m.store.SaveAgentNetworkPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to save agent network policy: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, policy.ID, policy.AccountID, activity.AgentNetworkPolicyUpdated, policy.EventMeta())
	m.reconcile(ctx, policy.AccountID)

	return policy, nil
}

func (m *managerImpl) DeletePolicy(ctx context.Context, accountID, userID, policyID string) error {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkPolicies, operations.Delete); err != nil {
		return err
	}

	policy, err := m.store.GetAgentNetworkPolicyByID(ctx, store.LockingStrengthUpdate, accountID, policyID)
	if err != nil {
		return fmt.Errorf("failed to get agent network policy: %w", err)
	}

	if err := m.store.DeleteAgentNetworkPolicy(ctx, accountID, policyID); err != nil {
		return fmt.Errorf("failed to delete agent network policy: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, policyID, accountID, activity.AgentNetworkPolicyDeleted, policy.EventMeta())
	m.reconcile(ctx, accountID)

	return nil
}

func (m *managerImpl) GetAllGuardrails(ctx context.Context, accountID, userID string) ([]*types.Guardrail, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkGuardrails, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetGuardrail(ctx context.Context, accountID, userID, guardrailID string) (*types.Guardrail, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkGuardrails, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAgentNetworkGuardrailByID(ctx, store.LockingStrengthNone, accountID, guardrailID)
}

func (m *managerImpl) CreateGuardrail(ctx context.Context, userID string, guardrail *types.Guardrail) (*types.Guardrail, error) {
	if err := m.requirePermission(ctx, guardrail.AccountID, userID, modules.AgentNetworkGuardrails, operations.Create); err != nil {
		return nil, err
	}

	if guardrail.ID == "" {
		fresh := types.NewGuardrail(guardrail.AccountID)
		guardrail.ID = fresh.ID
		guardrail.CreatedAt = fresh.CreatedAt
		guardrail.UpdatedAt = fresh.UpdatedAt
	}

	if err := m.store.SaveAgentNetworkGuardrail(ctx, guardrail); err != nil {
		return nil, fmt.Errorf("failed to save agent network guardrail: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, guardrail.ID, guardrail.AccountID, activity.AgentNetworkGuardrailCreated, guardrail.EventMeta())
	m.reconcile(ctx, guardrail.AccountID)

	return guardrail, nil
}

func (m *managerImpl) UpdateGuardrail(ctx context.Context, userID string, guardrail *types.Guardrail) (*types.Guardrail, error) {
	if err := m.requirePermission(ctx, guardrail.AccountID, userID, modules.AgentNetworkGuardrails, operations.Update); err != nil {
		return nil, err
	}

	existing, err := m.store.GetAgentNetworkGuardrailByID(ctx, store.LockingStrengthUpdate, guardrail.AccountID, guardrail.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent network guardrail: %w", err)
	}

	guardrail.CreatedAt = existing.CreatedAt
	guardrail.UpdatedAt = time.Now().UTC()

	if err := m.store.SaveAgentNetworkGuardrail(ctx, guardrail); err != nil {
		return nil, fmt.Errorf("failed to save agent network guardrail: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, guardrail.ID, guardrail.AccountID, activity.AgentNetworkGuardrailUpdated, guardrail.EventMeta())
	m.reconcile(ctx, guardrail.AccountID)

	return guardrail, nil
}

func (m *managerImpl) DeleteGuardrail(ctx context.Context, accountID, userID, guardrailID string) error {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkGuardrails, operations.Delete); err != nil {
		return err
	}

	guardrail, err := m.store.GetAgentNetworkGuardrailByID(ctx, store.LockingStrengthUpdate, accountID, guardrailID)
	if err != nil {
		return fmt.Errorf("failed to get agent network guardrail: %w", err)
	}

	if err := m.store.DeleteAgentNetworkGuardrail(ctx, accountID, guardrailID); err != nil {
		return fmt.Errorf("failed to delete agent network guardrail: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, guardrailID, accountID, activity.AgentNetworkGuardrailDeleted, guardrail.EventMeta())
	m.reconcile(ctx, accountID)

	return nil
}

// GetAllBudgetRules returns every account-level budget rule for the account.
func (m *managerImpl) GetAllBudgetRules(ctx context.Context, accountID, userID string) ([]*types.AccountBudgetRule, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkBudgets, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAccountAgentNetworkBudgetRules(ctx, store.LockingStrengthNone, accountID)
}

// GetBudgetRule returns a single account-level budget rule.
func (m *managerImpl) GetBudgetRule(ctx context.Context, accountID, userID, ruleID string) (*types.AccountBudgetRule, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkBudgets, operations.Read); err != nil {
		return nil, err
	}
	return m.store.GetAgentNetworkBudgetRuleByID(ctx, store.LockingStrengthNone, accountID, ruleID)
}

// CreateBudgetRule persists a new account-level budget rule. Budget rules are
// enforced at request time (CheckLLMPolicyLimits), not baked into the synth
// proxy config, so no reconcile is needed.
func (m *managerImpl) CreateBudgetRule(ctx context.Context, userID string, rule *types.AccountBudgetRule) (*types.AccountBudgetRule, error) {
	if err := m.requirePermission(ctx, rule.AccountID, userID, modules.AgentNetworkBudgets, operations.Create); err != nil {
		return nil, err
	}

	if rule.ID == "" {
		fresh := types.NewAccountBudgetRule(rule.AccountID)
		rule.ID = fresh.ID
		rule.CreatedAt = fresh.CreatedAt
		rule.UpdatedAt = fresh.UpdatedAt
	}

	if err := m.store.SaveAgentNetworkBudgetRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("save agent network budget rule: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, rule.ID, rule.AccountID, activity.AgentNetworkBudgetRuleCreated, rule.EventMeta())

	return rule, nil
}

// UpdateBudgetRule updates an existing account-level budget rule.
func (m *managerImpl) UpdateBudgetRule(ctx context.Context, userID string, rule *types.AccountBudgetRule) (*types.AccountBudgetRule, error) {
	if err := m.requirePermission(ctx, rule.AccountID, userID, modules.AgentNetworkBudgets, operations.Update); err != nil {
		return nil, err
	}

	existing, err := m.store.GetAgentNetworkBudgetRuleByID(ctx, store.LockingStrengthUpdate, rule.AccountID, rule.ID)
	if err != nil {
		return nil, fmt.Errorf("get agent network budget rule: %w", err)
	}

	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now().UTC()

	if err := m.store.SaveAgentNetworkBudgetRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("save agent network budget rule: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, rule.ID, rule.AccountID, activity.AgentNetworkBudgetRuleUpdated, rule.EventMeta())

	return rule, nil
}

// DeleteBudgetRule removes an account-level budget rule.
func (m *managerImpl) DeleteBudgetRule(ctx context.Context, accountID, userID, ruleID string) error {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkBudgets, operations.Delete); err != nil {
		return err
	}

	rule, err := m.store.GetAgentNetworkBudgetRuleByID(ctx, store.LockingStrengthUpdate, accountID, ruleID)
	if err != nil {
		return fmt.Errorf("get agent network budget rule: %w", err)
	}

	if err := m.store.DeleteAgentNetworkBudgetRule(ctx, accountID, ruleID); err != nil {
		return fmt.Errorf("delete agent network budget rule: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, ruleID, accountID, activity.AgentNetworkBudgetRuleDeleted, rule.EventMeta())

	return nil
}

// UpdateSettings replaces the mutable account-level settings — the collection
// toggles and retention — on the account's row. The identity fields (Domain,
// ProxyAddress) are assigned at bootstrap (CreateSettings) and are not part of
// the update surface at all; when the account has no settings row yet the
// update fails with NotFound. Because the collection toggles change the
// synthesised service config (prompt-capture gating, access-log emission), a
// reconcile is triggered so the proxy and peer network maps converge on the
// new state.
func (m *managerImpl) UpdateSettings(ctx context.Context, userID string, settings *types.Settings) (*types.Settings, error) {
	if err := m.requirePermission(ctx, settings.AccountID, userID, modules.AgentNetworkSettings, operations.Update); err != nil {
		return nil, err
	}

	// The row lock from LockingStrengthUpdate only holds for the duration of
	// the surrounding transaction, so the read and the save must share one —
	// otherwise concurrent PUTs could interleave between them.
	var updated *types.Settings
	err := m.store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		existing, err := tx.GetAgentNetworkSettings(ctx, store.LockingStrengthUpdate, settings.AccountID)
		switch {
		case err == nil:
		case isNotFound(err):
			return status.Errorf(status.NotFound, "agent network settings have not been bootstrapped yet; POST /api/agent-network/settings to bootstrap them")
		default:
			return fmt.Errorf("get agent network settings: %w", err)
		}

		existing.EnableLogCollection = settings.EnableLogCollection
		existing.EnablePromptCollection = settings.EnablePromptCollection
		existing.RedactPii = settings.RedactPii
		existing.AccessLogRetentionDays = settings.AccessLogRetentionDays
		existing.UpdatedAt = time.Now().UTC()

		if err := tx.SaveAgentNetworkSettings(ctx, existing); err != nil {
			return fmt.Errorf("save agent network settings: %w", err)
		}
		updated = existing
		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, settings.AccountID, settings.AccountID, activity.AgentNetworkSettingsUpdated, map[string]any{
		"log_collection":    updated.EnableLogCollection,
		"prompt_collection": updated.EnablePromptCollection,
		"redact_pii":        updated.RedactPii,
	})
	m.reconcile(ctx, settings.AccountID)

	return updated, nil
}

// isNotFound reports whether err is a status.NotFound error.
func isNotFound(err error) bool {
	var sErr *status.Error
	return errors.As(err, &sErr) && sErr.Type() == status.NotFound
}

// validateProviderRefs ensures every destination provider id refers to a
// provider that exists in the same account.
func (m *managerImpl) validateProviderRefs(ctx context.Context, accountID string, providerIDs []string) error {
	if len(providerIDs) == 0 {
		return nil
	}
	for _, id := range providerIDs {
		if _, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, accountID, id); err != nil {
			// Only a genuine not-found means the reference is invalid; a
			// store/runtime error must propagate as-is rather than be
			// masked as a client validation error.
			var sErr *status.Error
			if errors.As(err, &sErr) && sErr.Type() == status.NotFound {
				return status.Errorf(status.InvalidArgument, "destination_provider_ids: provider %s does not exist", id)
			}
			return fmt.Errorf("get destination provider %s: %w", id, err)
		}
	}
	return nil
}

// GetSettings returns the agent-network settings row for the account. When no
// row has been bootstrapped yet, the defaults are returned (without
// persisting) with cluster and subdomain empty — settings always read as an
// object, like the account and DNS settings endpoints.
func (m *managerImpl) GetSettings(ctx context.Context, accountID, userID string) (*types.Settings, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkSettings, operations.Read); err != nil {
		return nil, err
	}
	settings, err := m.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	switch {
	case err == nil:
		return settings, nil
	case isNotFound(err):
		return types.DefaultSettings(accountID), nil
	default:
		return nil, err
	}
}

// maxDomainAllocationAttempts bounds the label search when bootstrapping a
// labeled endpoint. Package-level (rather than function-local) so tests can
// assert on the exhaustion path without duplicating the literal.
const maxDomainAllocationAttempts = 10

// CreateSettings bootstraps the per-account settings row, assigning the
// account's immutable endpoint. Exactly one of proxyAddress and endpoint must
// be non-empty: proxyAddress allocates a labeled endpoint one label beneath
// the given cluster address; endpoint claims the given hostname verbatim as a
// self-addressed (dedicated) endpoint — a legitimate claim before any proxy
// declares the address (address-first). settings carries the account ID and
// the initial collection toggles; its identity fields are assigned here.
func (m *managerImpl) CreateSettings(ctx context.Context, userID string, settings *types.Settings, proxyAddress, endpoint string) (*types.Settings, error) {
	if settings == nil || settings.AccountID == "" {
		return nil, status.Errorf(status.InvalidArgument, "account id is required")
	}
	if err := m.requirePermission(ctx, settings.AccountID, userID, modules.AgentNetworkSettings, operations.Create); err != nil {
		return nil, err
	}

	hasProxyAddress := strings.TrimSpace(proxyAddress) != ""
	hasEndpoint := strings.TrimSpace(endpoint) != ""
	if hasProxyAddress == hasEndpoint {
		return nil, status.Errorf(status.InvalidArgument, "exactly one of proxy_address and endpoint is required")
	}

	// Fail fast on an existing row for a clean 409; the insert below stays
	// the authority against concurrent bootstraps (the primary key wins).
	if _, err := m.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, settings.AccountID); err == nil {
		return nil, status.Errorf(status.AlreadyExists, "agent network settings already bootstrapped for account %s", settings.AccountID)
	} else if !isNotFound(err) {
		return nil, fmt.Errorf("get agent network settings: %w", err)
	}

	now := time.Now().UTC()
	settings.CreatedAt = now
	settings.UpdatedAt = now

	var err error
	if hasEndpoint {
		err = m.bootstrapSelfAddressed(ctx, settings, endpoint)
	} else {
		err = m.bootstrapLabeled(ctx, settings, proxyAddress)
	}
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, settings.AccountID, settings.AccountID, activity.AgentNetworkSettingsUpdated, map[string]any{
		"bootstrapped": true,
		"endpoint":     settings.Domain,
		"dedicated":    settings.Dedicated(),
	})
	m.reconcile(ctx, settings.AccountID)

	return settings, nil
}

// bootstrapSelfAddressed claims the given hostname as the account's endpoint,
// served only by a proxy declaring exactly that address (Domain ==
// ProxyAddress). The domain unique index is the arbiter of availability.
func (m *managerImpl) bootstrapSelfAddressed(ctx context.Context, settings *types.Settings, endpoint string) error {
	hostname, err := types.NormalizeHostname(endpoint)
	if err != nil {
		return status.Errorf(status.InvalidArgument, "invalid endpoint: %s", err)
	}

	settings.Domain = hostname
	settings.ProxyAddress = hostname
	if err := m.store.CreateAgentNetworkSettings(ctx, settings); err != nil {
		if isUniqueConstraintError(err) {
			// The violation is either the account primary key (a concurrent
			// bootstrap for the same account won) or the domain index
			// (another account holds the hostname). Distinguish by re-read.
			if _, getErr := m.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, settings.AccountID); getErr == nil {
				return status.Errorf(status.AlreadyExists, "agent network settings already bootstrapped for account %s", settings.AccountID)
			}
			return status.Errorf(status.AlreadyExists, "endpoint %s is already taken", hostname)
		}
		return fmt.Errorf("create agent network settings: %w", err)
	}
	return nil
}

// bootstrapLabeled allocates a labeled endpoint one label beneath the given
// cluster address: Domain = <label>.<proxyAddress>, served by whichever proxy
// declares the parent. Labels are adjective-noun tuples; a candidate is
// checked by read and the domain unique index stays the authority, so a
// concurrent allocation of the same tuple surfaces as a unique violation and
// another tuple is drawn.
func (m *managerImpl) bootstrapLabeled(ctx context.Context, settings *types.Settings, proxyAddress string) error {
	parent, err := types.NormalizeHostname(proxyAddress)
	if err != nil {
		return status.Errorf(status.InvalidArgument, "invalid proxy_address: %s", err)
	}

	for attempt := 1; attempt <= maxDomainAllocationAttempts; attempt++ {
		m.labelRngMu.Lock()
		label := labelgen.PickTuple(m.labelRng)
		m.labelRngMu.Unlock()
		if label == "" {
			// Only reachable if either word pool were emptied. An empty label
			// would produce a broken endpoint like ".example.com", so fail
			// loudly rather than looping or inserting.
			return fmt.Errorf("allocate agent network endpoint for account %s: label generator returned an empty label", settings.AccountID)
		}

		candidate, err := types.NormalizeHostname(label + "." + parent)
		if err != nil {
			return status.Errorf(status.InvalidArgument, "proxy_address leaves no room for a label: %s", err)
		}

		_, err = m.store.GetAgentNetworkSettingsByDomain(ctx, store.LockingStrengthNone, candidate)
		if err == nil {
			log.WithContext(ctx).Tracef("agent-network endpoint %q taken, retrying (attempt %d/%d)", candidate, attempt, maxDomainAllocationAttempts)
			continue
		}
		if !isNotFound(err) {
			return fmt.Errorf("check agent network endpoint availability: %w", err)
		}

		settings.Domain = candidate
		settings.ProxyAddress = parent
		if err := m.store.CreateAgentNetworkSettings(ctx, settings); err != nil {
			if isUniqueConstraintError(err) {
				// A concurrent bootstrap for the same account may have won on
				// the primary key — return the conflict. A lost race on the
				// domain index just means the tuple was taken between the
				// read and the insert: draw another.
				if _, getErr := m.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, settings.AccountID); getErr == nil {
					return status.Errorf(status.AlreadyExists, "agent network settings already bootstrapped for account %s", settings.AccountID)
				}
				log.WithContext(ctx).Tracef("agent-network endpoint %q lost an allocation race, retrying (attempt %d/%d)", candidate, attempt, maxDomainAllocationAttempts)
				continue
			}
			return fmt.Errorf("create agent network settings: %w", err)
		}
		return nil
	}

	return fmt.Errorf("allocate agent network endpoint for account %s: %d attempts exhausted", settings.AccountID, maxDomainAllocationAttempts)
}

// isUniqueConstraintError reports whether err is a database unique-constraint
// violation, matched on the driver message because CreateAgentNetworkSettings
// deliberately returns the driver error unwrapped.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "(SQLSTATE 23505)") || // postgres
		strings.Contains(msg, "Error 1062 (23000)") || // mysql
		strings.Contains(msg, "UNIQUE constraint failed") // sqlite
}

// ListConsumption returns every consumption row recorded for the
// account, ordered window-newest-first. Backs the dashboard's basic
// counter view; permission gate is the same Read role that gates
// every other agent-network surface.
func (m *managerImpl) ListConsumption(ctx context.Context, accountID, userID string) ([]*types.Consumption, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkUsage, operations.Read); err != nil {
		return nil, err
	}
	return m.store.ListAgentNetworkConsumption(ctx, store.LockingStrengthNone, accountID)
}

// ListAccessLogs returns a paginated, server-side-filtered page of
// agent-network access logs plus the total count matching the filter.
func (m *managerImpl) ListAccessLogs(ctx context.Context, accountID, userID string, filter types.AgentNetworkAccessLogFilter) ([]*types.AgentNetworkAccessLog, int64, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkLogs, operations.Read); err != nil {
		return nil, 0, err
	}
	return m.store.GetAgentNetworkAccessLogs(ctx, store.LockingStrengthNone, accountID, filter)
}

// ListAccessLogSessions returns a paginated, server-side-filtered page of
// agent-network access logs grouped by session, plus the total number of
// sessions matching the filter.
func (m *managerImpl) ListAccessLogSessions(ctx context.Context, accountID, userID string, filter types.AgentNetworkAccessLogFilter) ([]*types.AgentNetworkAccessLogSession, int64, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkLogs, operations.Read); err != nil {
		return nil, 0, err
	}
	return m.store.GetAgentNetworkAccessLogSessions(ctx, store.LockingStrengthNone, accountID, filter)
}

// GetUsageOverview returns the filtered usage rows aggregated into time buckets
// at the requested granularity, oldest-first.
func (m *managerImpl) GetUsageOverview(ctx context.Context, accountID, userID string, filter types.AgentNetworkAccessLogFilter, granularity types.UsageGranularity) ([]*types.AgentNetworkUsageBucket, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkUsage, operations.Read); err != nil {
		return nil, err
	}
	rows, err := m.store.GetAgentNetworkUsageRows(ctx, store.LockingStrengthNone, accountID, filter)
	if err != nil {
		return nil, err
	}
	return types.AggregateUsageByGranularity(rows, granularity), nil
}

// StartAccessLogCleanup launches a background sweep that periodically deletes
// each account's agent-network access-log rows older than that account's
// AccessLogRetentionDays. Usage records are never swept. A non-positive
// interval defaults to 24h.
func (m *managerImpl) StartAccessLogCleanup(ctx context.Context, cleanupIntervalHours int) {
	if cleanupIntervalHours <= 0 {
		cleanupIntervalHours = 24
	}
	interval := time.Duration(cleanupIntervalHours) * time.Hour

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		m.cleanupAccessLogsOnce(ctx) // run once on startup
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.cleanupAccessLogsOnce(ctx)
			}
		}
	}()
}

// cleanupAccessLogsOnce sweeps every account's expired access-log rows against
// its configured retention. Best-effort: a per-account failure is logged and
// the sweep continues.
func (m *managerImpl) cleanupAccessLogsOnce(ctx context.Context) {
	settings, err := m.store.GetAllAgentNetworkSettings(ctx, store.LockingStrengthNone)
	if err != nil {
		log.WithContext(ctx).Errorf("agent-network access-log cleanup: list settings: %v", err)
		return
	}
	for _, s := range settings {
		if s.AccessLogRetentionDays <= 0 {
			continue // keep indefinitely
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -s.AccessLogRetentionDays)
		deleted, err := m.store.DeleteOldAgentNetworkAccessLogs(ctx, s.AccountID, cutoff)
		if err != nil {
			log.WithContext(ctx).Warnf("agent-network access-log cleanup for account %s: %v", s.AccountID, err)
			continue
		}
		if deleted > 0 {
			log.WithContext(ctx).Infof("agent-network access-log cleanup: deleted %d rows for account %s (retention %d days)", deleted, s.AccountID, s.AccessLogRetentionDays)
		}
	}
}

// RecordConsumption increments the (dim, window) counter by the
// supplied deltas. The window_start is computed from time.Now under
// the supplied window_seconds so callers don't have to pre-align —
// the proxy's post-flight path simply hands us tokens + cost and
// which dimension we're booking against.
func (m *managerImpl) RecordConsumption(ctx context.Context, accountID string, kind types.ConsumptionDimension, dimID string, windowSeconds, tokensIn, tokensOut int64, costUSD float64) error {
	if accountID == "" || dimID == "" || windowSeconds <= 0 {
		return status.Errorf(status.InvalidArgument, "account_id, dim_id and window_seconds must be set")
	}
	windowStart := types.WindowStart(time.Now(), windowSeconds)
	return m.store.IncrementAgentNetworkConsumption(ctx, accountID, kind, dimID, windowSeconds, windowStart, tokensIn, tokensOut, costUSD)
}

func (m *managerImpl) requirePermission(ctx context.Context, accountID, userID string, module modules.Module, op operations.Operation) error {
	ok, _, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, module, op)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}
	return nil
}

type mockManager struct{}

// NewManagerMock returns a no-op manager useful for tests.
func NewManagerMock() Manager {
	return &mockManager{}
}

func (*mockManager) GetAllProviders(_ context.Context, _, _ string) ([]*types.Provider, error) {
	return []*types.Provider{}, nil
}

func (*mockManager) GetProvider(_ context.Context, _, _, _ string) (*types.Provider, error) {
	return &types.Provider{}, nil
}

func (*mockManager) CreateProvider(_ context.Context, _ string, p *types.Provider) (*types.Provider, error) {
	return p, nil
}

func (*mockManager) UpdateProvider(_ context.Context, _ string, p *types.Provider) (*types.Provider, error) {
	return p, nil
}

func (*mockManager) DeleteProvider(_ context.Context, _, _, _ string) error { return nil }

func (*mockManager) GetAllPolicies(_ context.Context, _, _ string) ([]*types.Policy, error) {
	return []*types.Policy{}, nil
}

func (*mockManager) GetPolicy(_ context.Context, _, _, _ string) (*types.Policy, error) {
	return &types.Policy{}, nil
}

func (*mockManager) CreatePolicy(_ context.Context, _ string, p *types.Policy) (*types.Policy, error) {
	return p, nil
}

func (*mockManager) UpdatePolicy(_ context.Context, _ string, p *types.Policy) (*types.Policy, error) {
	return p, nil
}

func (*mockManager) DeletePolicy(_ context.Context, _, _, _ string) error { return nil }

func (*mockManager) GetAllGuardrails(_ context.Context, _, _ string) ([]*types.Guardrail, error) {
	return []*types.Guardrail{}, nil
}

func (*mockManager) GetGuardrail(_ context.Context, _, _, _ string) (*types.Guardrail, error) {
	return &types.Guardrail{}, nil
}

func (*mockManager) CreateGuardrail(_ context.Context, _ string, g *types.Guardrail) (*types.Guardrail, error) {
	return g, nil
}

func (*mockManager) UpdateGuardrail(_ context.Context, _ string, g *types.Guardrail) (*types.Guardrail, error) {
	return g, nil
}

func (*mockManager) DeleteGuardrail(_ context.Context, _, _, _ string) error { return nil }

func (*mockManager) GetAllBudgetRules(_ context.Context, _, _ string) ([]*types.AccountBudgetRule, error) {
	return []*types.AccountBudgetRule{}, nil
}

func (*mockManager) GetBudgetRule(_ context.Context, _, _, _ string) (*types.AccountBudgetRule, error) {
	return &types.AccountBudgetRule{}, nil
}

func (*mockManager) CreateBudgetRule(_ context.Context, _ string, r *types.AccountBudgetRule) (*types.AccountBudgetRule, error) {
	return r, nil
}

func (*mockManager) UpdateBudgetRule(_ context.Context, _ string, r *types.AccountBudgetRule) (*types.AccountBudgetRule, error) {
	return r, nil
}

func (*mockManager) DeleteBudgetRule(_ context.Context, _, _, _ string) error { return nil }

func (*mockManager) GetSettings(_ context.Context, accountID, _ string) (*types.Settings, error) {
	return types.DefaultSettings(accountID), nil
}

func (*mockManager) CreateSettings(_ context.Context, _ string, s *types.Settings, proxyAddress, endpoint string) (*types.Settings, error) {
	if endpoint != "" {
		s.Domain = endpoint
		s.ProxyAddress = endpoint
	} else {
		s.Domain = "mock." + proxyAddress
		s.ProxyAddress = proxyAddress
	}
	return s, nil
}

func (*mockManager) UpdateSettings(_ context.Context, _ string, s *types.Settings) (*types.Settings, error) {
	return s, nil
}

func (*mockManager) ListConsumption(_ context.Context, _, _ string) ([]*types.Consumption, error) {
	return nil, nil
}

func (*mockManager) ListAccessLogs(_ context.Context, _, _ string, _ types.AgentNetworkAccessLogFilter) ([]*types.AgentNetworkAccessLog, int64, error) {
	return nil, 0, nil
}

func (*mockManager) ListAccessLogSessions(_ context.Context, _, _ string, _ types.AgentNetworkAccessLogFilter) ([]*types.AgentNetworkAccessLogSession, int64, error) {
	return nil, 0, nil
}

func (*mockManager) GetUsageOverview(_ context.Context, _, _ string, _ types.AgentNetworkAccessLogFilter, _ types.UsageGranularity) ([]*types.AgentNetworkUsageBucket, error) {
	return nil, nil
}

func (*mockManager) StartAccessLogCleanup(_ context.Context, _ int) {}

func (*mockManager) RecordConsumption(_ context.Context, _ string, _ types.ConsumptionDimension, _ string, _, _, _ int64, _ float64) error {
	return nil
}

func (*mockManager) RecordAccountBudgetUsage(_ context.Context, _, _ string, _ []string, _, _ int64, _ float64) error {
	return nil
}

func (*mockManager) RecordUsage(_ context.Context, _ RecordUsageInput) error {
	return nil
}
