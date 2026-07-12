package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetAllAgentNetworkProviders returns Agent Network providers across
// every account. Used by the synthesizer to build the global service map.
func (s *SqlStore) GetAllAgentNetworkProviders(ctx context.Context, lockStrength LockingStrength) ([]*agentNetworkTypes.Provider, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var providers []*agentNetworkTypes.Provider
	if result := tx.Find(&providers); result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get all agent network providers from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get all agent network providers from store")
	}

	for _, provider := range providers {
		if err := provider.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			log.WithContext(ctx).Errorf("failed to decrypt agent network provider %s: %v", provider.ID, err)
			return nil, status.Errorf(status.Internal, "failed to decrypt agent network provider")
		}
	}

	return providers, nil
}

// GetAgentNetworkMetrics returns aggregated agent-network adoption + usage
// counts for the self-hosted metrics worker. Each value is a single cheap
// aggregate; token/cost are summed over the always-collected per-request usage
// ledger (independent of the log-collection toggle) so they reflect real usage.
func (s *SqlStore) GetAgentNetworkMetrics(ctx context.Context) (AgentNetworkMetrics, error) {
	var m AgentNetworkMetrics
	db := s.db.WithContext(ctx)

	// Providers + distinct adopting accounts in one round-trip.
	provRow := db.Model(&agentNetworkTypes.Provider{}).
		Select("COUNT(*) AS providers, COUNT(DISTINCT account_id) AS accounts").Row()
	if err := provRow.Scan(&m.Providers, &m.Accounts); err != nil {
		return AgentNetworkMetrics{}, fmt.Errorf("scan agent network provider metrics: %w", err)
	}

	if err := db.Model(&agentNetworkTypes.Policy{}).Count(&m.Policies).Error; err != nil {
		return AgentNetworkMetrics{}, fmt.Errorf("count agent network policies: %w", err)
	}

	if err := db.Model(&agentNetworkTypes.AccountBudgetRule{}).Count(&m.BudgetRules).Error; err != nil {
		return AgentNetworkMetrics{}, fmt.Errorf("count agent network budget rules: %w", err)
	}

	if err := db.Model(&agentNetworkTypes.Settings{}).
		Where("enable_log_collection = ?", true).Count(&m.LogCollectionEnabled).Error; err != nil {
		return AgentNetworkMetrics{}, fmt.Errorf("count agent network log-collection accounts: %w", err)
	}

	// COALESCE so an empty ledger scans as 0 instead of NULL.
	usageRow := db.Model(&agentNetworkTypes.AgentNetworkUsage{}).
		Select("COALESCE(SUM(input_tokens), 0) AS input_tokens, " +
			"COALESCE(SUM(output_tokens), 0) AS output_tokens, " +
			"COALESCE(SUM(cost_usd), 0) AS cost_usd").Row()
	if err := usageRow.Scan(&m.InputTokens, &m.OutputTokens, &m.CostUSD); err != nil {
		return AgentNetworkMetrics{}, fmt.Errorf("scan agent network usage metrics: %w", err)
	}

	return m, nil
}

func (s *SqlStore) GetAccountAgentNetworkProviders(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.Provider, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var providers []*agentNetworkTypes.Provider
	result := tx.Find(&providers, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get agent network providers from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network providers from store")
	}

	for _, provider := range providers {
		if err := provider.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			log.WithContext(ctx).Errorf("failed to decrypt agent network provider %s: %v", provider.ID, err)
			return nil, status.Errorf(status.Internal, "failed to decrypt agent network provider")
		}
	}

	return providers, nil
}

func (s *SqlStore) GetAgentNetworkProviderByID(ctx context.Context, lockStrength LockingStrength, accountID, providerID string) (*agentNetworkTypes.Provider, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var provider *agentNetworkTypes.Provider
	result := tx.Take(&provider, accountAndIDQueryCondition, accountID, providerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAgentNetworkProviderNotFoundError(providerID)
		}

		log.WithContext(ctx).Errorf("failed to get agent network provider from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network provider from store")
	}

	if err := provider.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to decrypt agent network provider %s: %v", provider.ID, err)
		return nil, status.Errorf(status.Internal, "failed to decrypt agent network provider")
	}

	return provider, nil
}

func (s *SqlStore) SaveAgentNetworkProvider(ctx context.Context, provider *agentNetworkTypes.Provider) error {
	providerCopy := provider.Copy()
	if err := providerCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt agent network provider %s: %v", provider.ID, err)
		return status.Errorf(status.Internal, "failed to encrypt agent network provider")
	}

	result := s.db.Save(providerCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save agent network provider to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save agent network provider to store")
	}

	return nil
}

func (s *SqlStore) DeleteAgentNetworkProvider(ctx context.Context, accountID, providerID string) error {
	result := s.db.Delete(&agentNetworkTypes.Provider{}, accountAndIDQueryCondition, accountID, providerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete agent network provider from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete agent network provider from store")
	}

	if result.RowsAffected == 0 {
		return status.NewAgentNetworkProviderNotFoundError(providerID)
	}

	return nil
}

func (s *SqlStore) GetAccountAgentNetworkPolicies(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.Policy, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policies []*agentNetworkTypes.Policy
	result := tx.Find(&policies, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get agent network policies from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network policies from store")
	}

	return policies, nil
}

func (s *SqlStore) GetAgentNetworkPolicyByID(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) (*agentNetworkTypes.Policy, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policy *agentNetworkTypes.Policy
	result := tx.Take(&policy, accountAndIDQueryCondition, accountID, policyID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAgentNetworkPolicyNotFoundError(policyID)
		}

		log.WithContext(ctx).Errorf("failed to get agent network policy from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network policy from store")
	}

	return policy, nil
}

func (s *SqlStore) SaveAgentNetworkPolicy(ctx context.Context, policy *agentNetworkTypes.Policy) error {
	result := s.db.Save(policy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save agent network policy to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save agent network policy to store")
	}

	return nil
}

func (s *SqlStore) DeleteAgentNetworkPolicy(ctx context.Context, accountID, policyID string) error {
	result := s.db.Delete(&agentNetworkTypes.Policy{}, accountAndIDQueryCondition, accountID, policyID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete agent network policy from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete agent network policy from store")
	}

	if result.RowsAffected == 0 {
		return status.NewAgentNetworkPolicyNotFoundError(policyID)
	}

	return nil
}

func (s *SqlStore) GetAccountAgentNetworkGuardrails(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.Guardrail, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var guardrails []*agentNetworkTypes.Guardrail
	result := tx.Find(&guardrails, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get agent network guardrails from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network guardrails from store")
	}

	return guardrails, nil
}

func (s *SqlStore) GetAgentNetworkGuardrailByID(ctx context.Context, lockStrength LockingStrength, accountID, guardrailID string) (*agentNetworkTypes.Guardrail, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var guardrail *agentNetworkTypes.Guardrail
	result := tx.Take(&guardrail, accountAndIDQueryCondition, accountID, guardrailID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAgentNetworkGuardrailNotFoundError(guardrailID)
		}

		log.WithContext(ctx).Errorf("failed to get agent network guardrail from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network guardrail from store")
	}

	return guardrail, nil
}

func (s *SqlStore) SaveAgentNetworkGuardrail(ctx context.Context, guardrail *agentNetworkTypes.Guardrail) error {
	result := s.db.Save(guardrail)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save agent network guardrail to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save agent network guardrail to store")
	}

	return nil
}

func (s *SqlStore) DeleteAgentNetworkGuardrail(ctx context.Context, accountID, guardrailID string) error {
	result := s.db.Delete(&agentNetworkTypes.Guardrail{}, accountAndIDQueryCondition, accountID, guardrailID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete agent network guardrail from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete agent network guardrail from store")
	}

	if result.RowsAffected == 0 {
		return status.NewAgentNetworkGuardrailNotFoundError(guardrailID)
	}

	return nil
}

// GetAgentNetworkSettings returns the per-account Agent Network
// settings row. Returns status.NotFound when no row exists.
func (s *SqlStore) GetAgentNetworkSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*agentNetworkTypes.Settings, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var settings agentNetworkTypes.Settings
	result := tx.Take(&settings, "account_id = ?", accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "agent network settings for account %s not found", accountID)
		}

		log.WithContext(ctx).Errorf("failed to get agent network settings from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network settings from store")
	}

	return &settings, nil
}

// GetAllAgentNetworkSettings returns every account's settings row. Used by the
// access-log retention sweep to learn each account's retention window.
func (s *SqlStore) GetAllAgentNetworkSettings(ctx context.Context, lockStrength LockingStrength) ([]*agentNetworkTypes.Settings, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var settings []*agentNetworkTypes.Settings
	if err := tx.Find(&settings).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to list agent network settings: %v", err)
		return nil, status.Errorf(status.Internal, "failed to list agent network settings")
	}
	return settings, nil
}

// GetAgentNetworkSettingsByCluster returns every Settings row pinned to
// the given proxy cluster. Used by the bootstrap label generator to
// build the set of subdomains already taken on a cluster.
func (s *SqlStore) GetAgentNetworkSettingsByCluster(ctx context.Context, lockStrength LockingStrength, cluster string) ([]*agentNetworkTypes.Settings, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var settings []*agentNetworkTypes.Settings
	result := tx.Find(&settings, "cluster = ?", cluster)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get agent network settings by cluster from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network settings by cluster from store")
	}

	return settings, nil
}

// SaveAgentNetworkSettings upserts the per-account Agent Network
// settings row.
func (s *SqlStore) SaveAgentNetworkSettings(ctx context.Context, settings *agentNetworkTypes.Settings) error {
	result := s.db.Save(settings)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save agent network settings to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save agent network settings to store")
	}

	return nil
}

// IncrementAgentNetworkConsumption atomically upserts the consumption
// row keyed on (account, dim_kind, dim_id, window_seconds, window_start)
// and adds the supplied deltas. Concurrent calls from multiple proxy
// nodes converge — the database performs the increment server-side via
// ON CONFLICT DO UPDATE so no read-modify-write race exists.
func (s *SqlStore) IncrementAgentNetworkConsumption(
	ctx context.Context,
	accountID string,
	kind agentNetworkTypes.ConsumptionDimension,
	dimID string,
	windowSeconds int64,
	windowStart time.Time,
	tokensIn, tokensOut int64,
	costUSD float64,
) error {
	if accountID == "" || dimID == "" || windowSeconds <= 0 {
		return status.Errorf(status.InvalidArgument, "account_id, dim_id and window_seconds must be set")
	}
	// Deltas are added server-side via ON CONFLICT; a negative or non-finite
	// value would silently decrement / poison the persisted totals.
	if tokensIn < 0 || tokensOut < 0 || costUSD < 0 || math.IsNaN(costUSD) || math.IsInf(costUSD, 0) {
		return status.Errorf(status.InvalidArgument, "consumption deltas must be non-negative and finite")
	}
	row := agentNetworkTypes.Consumption{
		AccountID:      accountID,
		DimensionKind:  kind,
		DimensionID:    dimID,
		WindowSeconds:  windowSeconds,
		WindowStartUTC: windowStart.UTC(),
		TokensInput:    tokensIn,
		TokensOutput:   tokensOut,
		CostUSD:        costUSD,
		UpdatedAt:      time.Now().UTC(),
	}
	const tbl = "agent_network_consumption"
	err := s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "account_id"},
			{Name: "dim_kind"},
			{Name: "dim_id"},
			{Name: "window_seconds"},
			{Name: "window_start_utc"},
		},
		DoUpdates: clause.Assignments(map[string]any{
			"tokens_input":  gorm.Expr(tbl+".tokens_input + ?", tokensIn),
			"tokens_output": gorm.Expr(tbl+".tokens_output + ?", tokensOut),
			"cost_usd":      gorm.Expr(tbl+".cost_usd + ?", costUSD),
			"updated_at":    time.Now().UTC(),
		}),
	}).Create(&row).Error
	if err != nil {
		log.WithContext(ctx).Errorf("failed to increment agent network consumption: %v", err)
		return status.Errorf(status.Internal, "failed to increment agent network consumption")
	}
	return nil
}

// GetAgentNetworkConsumption returns the consumption row for the exact
// window key. Returns a zero-valued row (not found mapped to zero) so
// callers can use the result as the headroom basis without nil checks.
func (s *SqlStore) GetAgentNetworkConsumption(
	ctx context.Context,
	lockStrength LockingStrength,
	accountID string,
	kind agentNetworkTypes.ConsumptionDimension,
	dimID string,
	windowSeconds int64,
	windowStart time.Time,
) (*agentNetworkTypes.Consumption, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}
	var row agentNetworkTypes.Consumption
	result := tx.Take(&row,
		"account_id = ? AND dim_kind = ? AND dim_id = ? AND window_seconds = ? AND window_start_utc = ?",
		accountID, kind, dimID, windowSeconds, windowStart.UTC())
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return &agentNetworkTypes.Consumption{
				AccountID:      accountID,
				DimensionKind:  kind,
				DimensionID:    dimID,
				WindowSeconds:  windowSeconds,
				WindowStartUTC: windowStart.UTC(),
			}, nil
		}
		log.WithContext(ctx).Errorf("failed to get agent network consumption: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network consumption")
	}
	return &row, nil
}

// GetAgentNetworkConsumptionBatch reads many consumption counters for one
// account in a single query, returning a map keyed by the exact
// ConsumptionKey. Missing counters are simply absent from the map (callers
// treat absence as a zero counter). Replaces the per-cap point reads the
// policy selector previously issued one at a time.
func (s *SqlStore) GetAgentNetworkConsumptionBatch(
	ctx context.Context,
	lockStrength LockingStrength,
	accountID string,
	keys []agentNetworkTypes.ConsumptionKey,
) (map[agentNetworkTypes.ConsumptionKey]*agentNetworkTypes.Consumption, error) {
	out := make(map[agentNetworkTypes.ConsumptionKey]*agentNetworkTypes.Consumption, len(keys))
	if len(keys) == 0 {
		return out, nil
	}

	// Collect the distinct dim ids, windows and window starts so a single
	// query scopes to exactly the current windows in play, then filter the
	// returned rows down to the exact requested keys.
	wanted := make(map[agentNetworkTypes.ConsumptionKey]struct{}, len(keys))
	dimSet := make(map[string]struct{})
	winSet := make(map[int64]struct{})
	startSet := make(map[time.Time]struct{})
	for _, k := range keys {
		k.WindowStartUTC = k.WindowStartUTC.UTC()
		wanted[k] = struct{}{}
		dimSet[k.DimID] = struct{}{}
		winSet[k.WindowSeconds] = struct{}{}
		startSet[k.WindowStartUTC] = struct{}{}
	}
	dimIDs := make([]string, 0, len(dimSet))
	for d := range dimSet {
		dimIDs = append(dimIDs, d)
	}
	windows := make([]int64, 0, len(winSet))
	for w := range winSet {
		windows = append(windows, w)
	}
	starts := make([]time.Time, 0, len(startSet))
	for t := range startSet {
		starts = append(starts, t)
	}

	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}
	var rows []*agentNetworkTypes.Consumption
	result := tx.Find(&rows,
		"account_id = ? AND dim_id IN ? AND window_seconds IN ? AND window_start_utc IN ?",
		accountID, dimIDs, windows, starts)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to batch-get agent network consumption: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network consumption")
	}
	for _, row := range rows {
		k := agentNetworkTypes.ConsumptionKey{
			Kind:           row.DimensionKind,
			DimID:          row.DimensionID,
			WindowSeconds:  row.WindowSeconds,
			WindowStartUTC: row.WindowStartUTC.UTC(),
		}
		if _, ok := wanted[k]; ok {
			out[k] = row
		}
	}
	return out, nil
}

// IncrementAgentNetworkConsumptionBatch applies the same usage delta to every
// supplied counter inside a single transaction, so all per-(dimension, window)
// counters a served request books are written atomically in one round-trip
// instead of one upsert per counter. Keys are deduplicated by the caller.
func (s *SqlStore) IncrementAgentNetworkConsumptionBatch(
	ctx context.Context,
	accountID string,
	keys []agentNetworkTypes.ConsumptionKey,
	tokensIn, tokensOut int64,
	costUSD float64,
) error {
	if accountID == "" {
		return status.Errorf(status.InvalidArgument, "account_id must be set")
	}
	if tokensIn < 0 || tokensOut < 0 || costUSD < 0 || math.IsNaN(costUSD) || math.IsInf(costUSD, 0) {
		return status.Errorf(status.InvalidArgument, "consumption deltas must be non-negative and finite")
	}
	if len(keys) == 0 {
		return nil
	}

	const tbl = "agent_network_consumption"
	err := s.db.Transaction(func(tx *gorm.DB) error {
		for _, k := range keys {
			if k.DimID == "" || k.WindowSeconds <= 0 {
				return status.Errorf(status.InvalidArgument, "dim_id and window_seconds must be set")
			}
			now := time.Now().UTC()
			row := agentNetworkTypes.Consumption{
				AccountID:      accountID,
				DimensionKind:  k.Kind,
				DimensionID:    k.DimID,
				WindowSeconds:  k.WindowSeconds,
				WindowStartUTC: k.WindowStartUTC.UTC(),
				TokensInput:    tokensIn,
				TokensOutput:   tokensOut,
				CostUSD:        costUSD,
				UpdatedAt:      now,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "account_id"},
					{Name: "dim_kind"},
					{Name: "dim_id"},
					{Name: "window_seconds"},
					{Name: "window_start_utc"},
				},
				DoUpdates: clause.Assignments(map[string]any{
					"tokens_input":  gorm.Expr(tbl+".tokens_input + ?", tokensIn),
					"tokens_output": gorm.Expr(tbl+".tokens_output + ?", tokensOut),
					"cost_usd":      gorm.Expr(tbl+".cost_usd + ?", costUSD),
					"updated_at":    now,
				}),
			}).Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to batch-increment agent network consumption: %v", err)
		return status.Errorf(status.Internal, "failed to increment agent network consumption")
	}
	return nil
}

// ListAgentNetworkConsumption returns every consumption row recorded
// for the account, ordered by window_start descending. Backs the
// dashboard's basic counter view.
func (s *SqlStore) ListAgentNetworkConsumption(
	ctx context.Context,
	lockStrength LockingStrength,
	accountID string,
) ([]*agentNetworkTypes.Consumption, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}
	var rows []*agentNetworkTypes.Consumption
	result := tx.
		Order("window_start_utc DESC").
		Find(&rows, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list agent network consumption: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to list agent network consumption")
	}
	return rows, nil
}

// GetAccountAgentNetworkBudgetRules returns every account-level budget rule for
// the account.
func (s *SqlStore) GetAccountAgentNetworkBudgetRules(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.AccountBudgetRule, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var rules []*agentNetworkTypes.AccountBudgetRule
	result := tx.Find(&rules, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get agent network budget rules from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network budget rules from store")
	}

	return rules, nil
}

// GetAgentNetworkBudgetRuleByID returns a single budget rule scoped to the
// account, or a NotFound error.
func (s *SqlStore) GetAgentNetworkBudgetRuleByID(ctx context.Context, lockStrength LockingStrength, accountID, ruleID string) (*agentNetworkTypes.AccountBudgetRule, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var rule *agentNetworkTypes.AccountBudgetRule
	result := tx.Take(&rule, accountAndIDQueryCondition, accountID, ruleID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAgentNetworkBudgetRuleNotFoundError(ruleID)
		}

		log.WithContext(ctx).Errorf("failed to get agent network budget rule from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network budget rule from store")
	}

	return rule, nil
}

// SaveAgentNetworkBudgetRule upserts a budget rule.
func (s *SqlStore) SaveAgentNetworkBudgetRule(ctx context.Context, rule *agentNetworkTypes.AccountBudgetRule) error {
	result := s.db.Save(rule)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save agent network budget rule to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save agent network budget rule to store")
	}

	return nil
}

// DeleteAgentNetworkBudgetRule removes a budget rule scoped to the account.
func (s *SqlStore) DeleteAgentNetworkBudgetRule(ctx context.Context, accountID, ruleID string) error {
	result := s.db.Delete(&agentNetworkTypes.AccountBudgetRule{}, accountAndIDQueryCondition, accountID, ruleID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete agent network budget rule from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete agent network budget rule from store")
	}

	if result.RowsAffected == 0 {
		return status.NewAgentNetworkBudgetRuleNotFoundError(ruleID)
	}

	return nil
}
