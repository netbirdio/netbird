package store

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

// GetAllAgentNetworkProviders mocks base method.
func (m *MockStore) GetAllAgentNetworkProviders(ctx context.Context, lockStrength LockingStrength) ([]*agentNetworkTypes.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllAgentNetworkProviders", ctx, lockStrength)
	ret0, _ := ret[0].([]*agentNetworkTypes.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllAgentNetworkProviders indicates an expected call of GetAllAgentNetworkProviders.
func (mr *MockStoreMockRecorder) GetAllAgentNetworkProviders(ctx, lockStrength interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllAgentNetworkProviders", reflect.TypeOf((*MockStore)(nil).GetAllAgentNetworkProviders), ctx, lockStrength)
}

// GetAgentNetworkMetrics mocks base method.
func (m *MockStore) GetAgentNetworkMetrics(ctx context.Context) (AgentNetworkMetrics, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkMetrics", ctx)
	ret0, _ := ret[0].(AgentNetworkMetrics)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkMetrics indicates an expected call of GetAgentNetworkMetrics.
func (mr *MockStoreMockRecorder) GetAgentNetworkMetrics(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkMetrics", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkMetrics), ctx)
}

// GetAccountAgentNetworkProviders mocks base method.
func (m *MockStore) GetAccountAgentNetworkProviders(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountAgentNetworkProviders", ctx, lockStrength, accountID)
	ret0, _ := ret[0].([]*agentNetworkTypes.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccountAgentNetworkProviders indicates an expected call of GetAccountAgentNetworkProviders.
func (mr *MockStoreMockRecorder) GetAccountAgentNetworkProviders(ctx, lockStrength, accountID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountAgentNetworkProviders", reflect.TypeOf((*MockStore)(nil).GetAccountAgentNetworkProviders), ctx, lockStrength, accountID)
}

// GetAgentNetworkProviderByID mocks base method.
func (m *MockStore) GetAgentNetworkProviderByID(ctx context.Context, lockStrength LockingStrength, accountID, providerID string) (*agentNetworkTypes.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkProviderByID", ctx, lockStrength, accountID, providerID)
	ret0, _ := ret[0].(*agentNetworkTypes.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkProviderByID indicates an expected call of GetAgentNetworkProviderByID.
func (mr *MockStoreMockRecorder) GetAgentNetworkProviderByID(ctx, lockStrength, accountID, providerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkProviderByID", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkProviderByID), ctx, lockStrength, accountID, providerID)
}

// SaveAgentNetworkProvider mocks base method.
func (m *MockStore) SaveAgentNetworkProvider(ctx context.Context, provider *agentNetworkTypes.Provider) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveAgentNetworkProvider", ctx, provider)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveAgentNetworkProvider indicates an expected call of SaveAgentNetworkProvider.
func (mr *MockStoreMockRecorder) SaveAgentNetworkProvider(ctx, provider interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveAgentNetworkProvider", reflect.TypeOf((*MockStore)(nil).SaveAgentNetworkProvider), ctx, provider)
}

// DeleteAgentNetworkProvider mocks base method.
func (m *MockStore) DeleteAgentNetworkProvider(ctx context.Context, accountID, providerID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAgentNetworkProvider", ctx, accountID, providerID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAgentNetworkProvider indicates an expected call of DeleteAgentNetworkProvider.
func (mr *MockStoreMockRecorder) DeleteAgentNetworkProvider(ctx, accountID, providerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAgentNetworkProvider", reflect.TypeOf((*MockStore)(nil).DeleteAgentNetworkProvider), ctx, accountID, providerID)
}

// GetAccountAgentNetworkPolicies mocks base method.
func (m *MockStore) GetAccountAgentNetworkPolicies(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.Policy, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountAgentNetworkPolicies", ctx, lockStrength, accountID)
	ret0, _ := ret[0].([]*agentNetworkTypes.Policy)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccountAgentNetworkPolicies indicates an expected call of GetAccountAgentNetworkPolicies.
func (mr *MockStoreMockRecorder) GetAccountAgentNetworkPolicies(ctx, lockStrength, accountID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountAgentNetworkPolicies", reflect.TypeOf((*MockStore)(nil).GetAccountAgentNetworkPolicies), ctx, lockStrength, accountID)
}

// GetAgentNetworkPolicyByID mocks base method.
func (m *MockStore) GetAgentNetworkPolicyByID(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) (*agentNetworkTypes.Policy, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkPolicyByID", ctx, lockStrength, accountID, policyID)
	ret0, _ := ret[0].(*agentNetworkTypes.Policy)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkPolicyByID indicates an expected call of GetAgentNetworkPolicyByID.
func (mr *MockStoreMockRecorder) GetAgentNetworkPolicyByID(ctx, lockStrength, accountID, policyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkPolicyByID", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkPolicyByID), ctx, lockStrength, accountID, policyID)
}

// SaveAgentNetworkPolicy mocks base method.
func (m *MockStore) SaveAgentNetworkPolicy(ctx context.Context, policy *agentNetworkTypes.Policy) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveAgentNetworkPolicy", ctx, policy)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveAgentNetworkPolicy indicates an expected call of SaveAgentNetworkPolicy.
func (mr *MockStoreMockRecorder) SaveAgentNetworkPolicy(ctx, policy interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveAgentNetworkPolicy", reflect.TypeOf((*MockStore)(nil).SaveAgentNetworkPolicy), ctx, policy)
}

// DeleteAgentNetworkPolicy mocks base method.
func (m *MockStore) DeleteAgentNetworkPolicy(ctx context.Context, accountID, policyID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAgentNetworkPolicy", ctx, accountID, policyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAgentNetworkPolicy indicates an expected call of DeleteAgentNetworkPolicy.
func (mr *MockStoreMockRecorder) DeleteAgentNetworkPolicy(ctx, accountID, policyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAgentNetworkPolicy", reflect.TypeOf((*MockStore)(nil).DeleteAgentNetworkPolicy), ctx, accountID, policyID)
}

// GetAccountAgentNetworkGuardrails mocks base method.
func (m *MockStore) GetAccountAgentNetworkGuardrails(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.Guardrail, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountAgentNetworkGuardrails", ctx, lockStrength, accountID)
	ret0, _ := ret[0].([]*agentNetworkTypes.Guardrail)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccountAgentNetworkGuardrails indicates an expected call of GetAccountAgentNetworkGuardrails.
func (mr *MockStoreMockRecorder) GetAccountAgentNetworkGuardrails(ctx, lockStrength, accountID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountAgentNetworkGuardrails", reflect.TypeOf((*MockStore)(nil).GetAccountAgentNetworkGuardrails), ctx, lockStrength, accountID)
}

// GetAgentNetworkGuardrailByID mocks base method.
func (m *MockStore) GetAgentNetworkGuardrailByID(ctx context.Context, lockStrength LockingStrength, accountID, guardrailID string) (*agentNetworkTypes.Guardrail, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkGuardrailByID", ctx, lockStrength, accountID, guardrailID)
	ret0, _ := ret[0].(*agentNetworkTypes.Guardrail)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkGuardrailByID indicates an expected call of GetAgentNetworkGuardrailByID.
func (mr *MockStoreMockRecorder) GetAgentNetworkGuardrailByID(ctx, lockStrength, accountID, guardrailID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkGuardrailByID", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkGuardrailByID), ctx, lockStrength, accountID, guardrailID)
}

// SaveAgentNetworkGuardrail mocks base method.
func (m *MockStore) SaveAgentNetworkGuardrail(ctx context.Context, guardrail *agentNetworkTypes.Guardrail) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveAgentNetworkGuardrail", ctx, guardrail)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveAgentNetworkGuardrail indicates an expected call of SaveAgentNetworkGuardrail.
func (mr *MockStoreMockRecorder) SaveAgentNetworkGuardrail(ctx, guardrail interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveAgentNetworkGuardrail", reflect.TypeOf((*MockStore)(nil).SaveAgentNetworkGuardrail), ctx, guardrail)
}

// DeleteAgentNetworkGuardrail mocks base method.
func (m *MockStore) DeleteAgentNetworkGuardrail(ctx context.Context, accountID, guardrailID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAgentNetworkGuardrail", ctx, accountID, guardrailID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAgentNetworkGuardrail indicates an expected call of DeleteAgentNetworkGuardrail.
func (mr *MockStoreMockRecorder) DeleteAgentNetworkGuardrail(ctx, accountID, guardrailID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAgentNetworkGuardrail", reflect.TypeOf((*MockStore)(nil).DeleteAgentNetworkGuardrail), ctx, accountID, guardrailID)
}

// GetAgentNetworkSettings mocks base method.
func (m *MockStore) GetAgentNetworkSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*agentNetworkTypes.Settings, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkSettings", ctx, lockStrength, accountID)
	ret0, _ := ret[0].(*agentNetworkTypes.Settings)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkSettings indicates an expected call of GetAgentNetworkSettings.
func (mr *MockStoreMockRecorder) GetAgentNetworkSettings(ctx, lockStrength, accountID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkSettings", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkSettings), ctx, lockStrength, accountID)
}

// GetAgentNetworkSettingsByCluster mocks base method.
func (m *MockStore) GetAgentNetworkSettingsByCluster(ctx context.Context, lockStrength LockingStrength, cluster string) ([]*agentNetworkTypes.Settings, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkSettingsByCluster", ctx, lockStrength, cluster)
	ret0, _ := ret[0].([]*agentNetworkTypes.Settings)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkSettingsByCluster indicates an expected call of GetAgentNetworkSettingsByCluster.
func (mr *MockStoreMockRecorder) GetAgentNetworkSettingsByCluster(ctx, lockStrength, cluster interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkSettingsByCluster", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkSettingsByCluster), ctx, lockStrength, cluster)
}

// SaveAgentNetworkSettings mocks base method.
func (m *MockStore) SaveAgentNetworkSettings(ctx context.Context, settings *agentNetworkTypes.Settings) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveAgentNetworkSettings", ctx, settings)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveAgentNetworkSettings indicates an expected call of SaveAgentNetworkSettings.
func (mr *MockStoreMockRecorder) SaveAgentNetworkSettings(ctx, settings interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveAgentNetworkSettings", reflect.TypeOf((*MockStore)(nil).SaveAgentNetworkSettings), ctx, settings)
}

// IncrementAgentNetworkConsumption mocks base method.
func (m *MockStore) IncrementAgentNetworkConsumption(ctx context.Context, accountID string, kind agentNetworkTypes.ConsumptionDimension, dimID string, windowSeconds int64, windowStart time.Time, tokensIn, tokensOut int64, costUSD float64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IncrementAgentNetworkConsumption", ctx, accountID, kind, dimID, windowSeconds, windowStart, tokensIn, tokensOut, costUSD)
	ret0, _ := ret[0].(error)
	return ret0
}

// IncrementAgentNetworkConsumption indicates an expected call of IncrementAgentNetworkConsumption.
func (mr *MockStoreMockRecorder) IncrementAgentNetworkConsumption(ctx, accountID, kind, dimID, windowSeconds, windowStart, tokensIn, tokensOut, costUSD interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IncrementAgentNetworkConsumption", reflect.TypeOf((*MockStore)(nil).IncrementAgentNetworkConsumption), ctx, accountID, kind, dimID, windowSeconds, windowStart, tokensIn, tokensOut, costUSD)
}

// GetAgentNetworkConsumption mocks base method.
func (m *MockStore) GetAgentNetworkConsumption(ctx context.Context, lockStrength LockingStrength, accountID string, kind agentNetworkTypes.ConsumptionDimension, dimID string, windowSeconds int64, windowStart time.Time) (*agentNetworkTypes.Consumption, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkConsumption", ctx, lockStrength, accountID, kind, dimID, windowSeconds, windowStart)
	ret0, _ := ret[0].(*agentNetworkTypes.Consumption)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkConsumption indicates an expected call of GetAgentNetworkConsumption.
func (mr *MockStoreMockRecorder) GetAgentNetworkConsumption(ctx, lockStrength, accountID, kind, dimID, windowSeconds, windowStart interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkConsumption", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkConsumption), ctx, lockStrength, accountID, kind, dimID, windowSeconds, windowStart)
}

// GetAgentNetworkConsumptionBatch mocks base method.
func (m *MockStore) GetAgentNetworkConsumptionBatch(ctx context.Context, lockStrength LockingStrength, accountID string, keys []agentNetworkTypes.ConsumptionKey) (map[agentNetworkTypes.ConsumptionKey]*agentNetworkTypes.Consumption, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkConsumptionBatch", ctx, lockStrength, accountID, keys)
	ret0, _ := ret[0].(map[agentNetworkTypes.ConsumptionKey]*agentNetworkTypes.Consumption)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkConsumptionBatch indicates an expected call of GetAgentNetworkConsumptionBatch.
func (mr *MockStoreMockRecorder) GetAgentNetworkConsumptionBatch(ctx, lockStrength, accountID, keys interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkConsumptionBatch", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkConsumptionBatch), ctx, lockStrength, accountID, keys)
}

// IncrementAgentNetworkConsumptionBatch mocks base method.
func (m *MockStore) IncrementAgentNetworkConsumptionBatch(ctx context.Context, accountID string, keys []agentNetworkTypes.ConsumptionKey, tokensIn, tokensOut int64, costUSD float64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IncrementAgentNetworkConsumptionBatch", ctx, accountID, keys, tokensIn, tokensOut, costUSD)
	ret0, _ := ret[0].(error)
	return ret0
}

// IncrementAgentNetworkConsumptionBatch indicates an expected call of IncrementAgentNetworkConsumptionBatch.
func (mr *MockStoreMockRecorder) IncrementAgentNetworkConsumptionBatch(ctx, accountID, keys, tokensIn, tokensOut, costUSD interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IncrementAgentNetworkConsumptionBatch", reflect.TypeOf((*MockStore)(nil).IncrementAgentNetworkConsumptionBatch), ctx, accountID, keys, tokensIn, tokensOut, costUSD)
}

// ListAgentNetworkConsumption mocks base method.
func (m *MockStore) ListAgentNetworkConsumption(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.Consumption, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListAgentNetworkConsumption", ctx, lockStrength, accountID)
	ret0, _ := ret[0].([]*agentNetworkTypes.Consumption)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListAgentNetworkConsumption indicates an expected call of ListAgentNetworkConsumption.
func (mr *MockStoreMockRecorder) ListAgentNetworkConsumption(ctx, lockStrength, accountID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListAgentNetworkConsumption", reflect.TypeOf((*MockStore)(nil).ListAgentNetworkConsumption), ctx, lockStrength, accountID)
}

// GetAccountAgentNetworkBudgetRules mocks base method.
func (m *MockStore) GetAccountAgentNetworkBudgetRules(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*agentNetworkTypes.AccountBudgetRule, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountAgentNetworkBudgetRules", ctx, lockStrength, accountID)
	ret0, _ := ret[0].([]*agentNetworkTypes.AccountBudgetRule)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccountAgentNetworkBudgetRules indicates an expected call of GetAccountAgentNetworkBudgetRules.
func (mr *MockStoreMockRecorder) GetAccountAgentNetworkBudgetRules(ctx, lockStrength, accountID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountAgentNetworkBudgetRules", reflect.TypeOf((*MockStore)(nil).GetAccountAgentNetworkBudgetRules), ctx, lockStrength, accountID)
}

// GetAgentNetworkBudgetRuleByID mocks base method.
func (m *MockStore) GetAgentNetworkBudgetRuleByID(ctx context.Context, lockStrength LockingStrength, accountID, ruleID string) (*agentNetworkTypes.AccountBudgetRule, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkBudgetRuleByID", ctx, lockStrength, accountID, ruleID)
	ret0, _ := ret[0].(*agentNetworkTypes.AccountBudgetRule)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkBudgetRuleByID indicates an expected call of GetAgentNetworkBudgetRuleByID.
func (mr *MockStoreMockRecorder) GetAgentNetworkBudgetRuleByID(ctx, lockStrength, accountID, ruleID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkBudgetRuleByID", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkBudgetRuleByID), ctx, lockStrength, accountID, ruleID)
}

// SaveAgentNetworkBudgetRule mocks base method.
func (m *MockStore) SaveAgentNetworkBudgetRule(ctx context.Context, rule *agentNetworkTypes.AccountBudgetRule) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveAgentNetworkBudgetRule", ctx, rule)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveAgentNetworkBudgetRule indicates an expected call of SaveAgentNetworkBudgetRule.
func (mr *MockStoreMockRecorder) SaveAgentNetworkBudgetRule(ctx, rule interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveAgentNetworkBudgetRule", reflect.TypeOf((*MockStore)(nil).SaveAgentNetworkBudgetRule), ctx, rule)
}

// DeleteAgentNetworkBudgetRule mocks base method.
func (m *MockStore) DeleteAgentNetworkBudgetRule(ctx context.Context, accountID, ruleID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAgentNetworkBudgetRule", ctx, accountID, ruleID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAgentNetworkBudgetRule indicates an expected call of DeleteAgentNetworkBudgetRule.
func (mr *MockStoreMockRecorder) DeleteAgentNetworkBudgetRule(ctx, accountID, ruleID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAgentNetworkBudgetRule", reflect.TypeOf((*MockStore)(nil).DeleteAgentNetworkBudgetRule), ctx, accountID, ruleID)
}

// CreateAgentNetworkAccessLog mocks base method.
func (m *MockStore) CreateAgentNetworkAccessLog(ctx context.Context, entry *agentNetworkTypes.AgentNetworkAccessLog, groups []agentNetworkTypes.AgentNetworkAccessLogGroup) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAgentNetworkAccessLog", ctx, entry, groups)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAgentNetworkAccessLog indicates an expected call of CreateAgentNetworkAccessLog.
func (mr *MockStoreMockRecorder) CreateAgentNetworkAccessLog(ctx, entry, groups interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAgentNetworkAccessLog", reflect.TypeOf((*MockStore)(nil).CreateAgentNetworkAccessLog), ctx, entry, groups)
}

// CreateAgentNetworkUsage mocks base method.
func (m *MockStore) CreateAgentNetworkUsage(ctx context.Context, usage *agentNetworkTypes.AgentNetworkUsage, groups []agentNetworkTypes.AgentNetworkUsageGroup) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAgentNetworkUsage", ctx, usage, groups)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAgentNetworkUsage indicates an expected call of CreateAgentNetworkUsage.
func (mr *MockStoreMockRecorder) CreateAgentNetworkUsage(ctx, usage, groups interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAgentNetworkUsage", reflect.TypeOf((*MockStore)(nil).CreateAgentNetworkUsage), ctx, usage, groups)
}

// GetAgentNetworkAccessLogs mocks base method.
func (m *MockStore) GetAgentNetworkAccessLogs(ctx context.Context, lockStrength LockingStrength, accountID string, filter agentNetworkTypes.AgentNetworkAccessLogFilter) ([]*agentNetworkTypes.AgentNetworkAccessLog, int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkAccessLogs", ctx, lockStrength, accountID, filter)
	ret0, _ := ret[0].([]*agentNetworkTypes.AgentNetworkAccessLog)
	ret1, _ := ret[1].(int64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetAgentNetworkAccessLogs indicates an expected call of GetAgentNetworkAccessLogs.
func (mr *MockStoreMockRecorder) GetAgentNetworkAccessLogs(ctx, lockStrength, accountID, filter interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkAccessLogs", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkAccessLogs), ctx, lockStrength, accountID, filter)
}

// GetAgentNetworkUsageRows mocks base method.
func (m *MockStore) GetAgentNetworkUsageRows(ctx context.Context, lockStrength LockingStrength, accountID string, filter agentNetworkTypes.AgentNetworkAccessLogFilter) ([]*agentNetworkTypes.AgentNetworkUsage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAgentNetworkUsageRows", ctx, lockStrength, accountID, filter)
	ret0, _ := ret[0].([]*agentNetworkTypes.AgentNetworkUsage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAgentNetworkUsageRows indicates an expected call of GetAgentNetworkUsageRows.
func (mr *MockStoreMockRecorder) GetAgentNetworkUsageRows(ctx, lockStrength, accountID, filter interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentNetworkUsageRows", reflect.TypeOf((*MockStore)(nil).GetAgentNetworkUsageRows), ctx, lockStrength, accountID, filter)
}

// DeleteOldAgentNetworkAccessLogs mocks base method.
func (m *MockStore) DeleteOldAgentNetworkAccessLogs(ctx context.Context, accountID string, olderThan time.Time) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteOldAgentNetworkAccessLogs", ctx, accountID, olderThan)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteOldAgentNetworkAccessLogs indicates an expected call of DeleteOldAgentNetworkAccessLogs.
func (mr *MockStoreMockRecorder) DeleteOldAgentNetworkAccessLogs(ctx, accountID, olderThan interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteOldAgentNetworkAccessLogs", reflect.TypeOf((*MockStore)(nil).DeleteOldAgentNetworkAccessLogs), ctx, accountID, olderThan)
}

// GetAllAgentNetworkSettings mocks base method.
func (m *MockStore) GetAllAgentNetworkSettings(ctx context.Context, lockStrength LockingStrength) ([]*agentNetworkTypes.Settings, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllAgentNetworkSettings", ctx, lockStrength)
	ret0, _ := ret[0].([]*agentNetworkTypes.Settings)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllAgentNetworkSettings indicates an expected call of GetAllAgentNetworkSettings.
func (mr *MockStoreMockRecorder) GetAllAgentNetworkSettings(ctx, lockStrength interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllAgentNetworkSettings", reflect.TypeOf((*MockStore)(nil).GetAllAgentNetworkSettings), ctx, lockStrength)
}
