package entra_device

import (
	"context"

	"github.com/netbirdio/netbird/management/server/types"
)

// Store is the persistence surface this package needs. It is intentionally
// *not* added to the global management store.Store interface so the main
// storage layer stays unchanged in Phase 1 — we wire it up later by having the
// SQL store embed these methods and satisfy this interface.
type Store interface {
	// Integration CRUD
	GetEntraDeviceAuth(ctx context.Context, accountID string) (*types.EntraDeviceAuth, error)
	GetEntraDeviceAuthByTenant(ctx context.Context, tenantID string) (*types.EntraDeviceAuth, error)
	SaveEntraDeviceAuth(ctx context.Context, auth *types.EntraDeviceAuth) error
	DeleteEntraDeviceAuth(ctx context.Context, accountID string) error

	// Mapping CRUD
	ListEntraDeviceMappings(ctx context.Context, accountID string) ([]*types.EntraDeviceAuthMapping, error)
	GetEntraDeviceMapping(ctx context.Context, accountID, mappingID string) (*types.EntraDeviceAuthMapping, error)
	SaveEntraDeviceMapping(ctx context.Context, mapping *types.EntraDeviceAuthMapping) error
	DeleteEntraDeviceMapping(ctx context.Context, accountID, mappingID string) error

	// BootstrapToken caching for the post-enrolment gRPC Login hand-off.
	StoreBootstrapToken(ctx context.Context, peerID, token string) error
	ConsumeBootstrapToken(ctx context.Context, peerID, token string) (bool, error)
}

// MemoryStore is an in-memory Store implementation used by tests and by the
// initial admin bring-up when the SQL wiring isn't yet in place. It is goroutine-
// safe.
//
// Production deployments MUST swap this for the SQL-backed implementation in
// management/server/store — see the README for the wiring path.
type MemoryStore struct {
	auths    map[string]*types.EntraDeviceAuth              // keyed by accountID
	byTenant map[string]*types.EntraDeviceAuth              // keyed by tenantID
	mappings map[string]map[string]*types.EntraDeviceAuthMapping
	tokens   map[string]string // peerID -> token
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		auths:    map[string]*types.EntraDeviceAuth{},
		byTenant: map[string]*types.EntraDeviceAuth{},
		mappings: map[string]map[string]*types.EntraDeviceAuthMapping{},
		tokens:   map[string]string{},
	}
}

// --- integration ---

func (m *MemoryStore) GetEntraDeviceAuth(_ context.Context, accountID string) (*types.EntraDeviceAuth, error) {
	if a, ok := m.auths[accountID]; ok {
		return a, nil
	}
	return nil, nil
}

func (m *MemoryStore) GetEntraDeviceAuthByTenant(_ context.Context, tenantID string) (*types.EntraDeviceAuth, error) {
	if a, ok := m.byTenant[tenantID]; ok {
		return a, nil
	}
	return nil, nil
}

func (m *MemoryStore) SaveEntraDeviceAuth(_ context.Context, auth *types.EntraDeviceAuth) error {
	m.auths[auth.AccountID] = auth
	if auth.TenantID != "" {
		m.byTenant[auth.TenantID] = auth
	}
	return nil
}

func (m *MemoryStore) DeleteEntraDeviceAuth(_ context.Context, accountID string) error {
	if a, ok := m.auths[accountID]; ok {
		delete(m.byTenant, a.TenantID)
	}
	delete(m.auths, accountID)
	delete(m.mappings, accountID)
	return nil
}

// --- mappings ---

func (m *MemoryStore) ListEntraDeviceMappings(_ context.Context, accountID string) ([]*types.EntraDeviceAuthMapping, error) {
	inner := m.mappings[accountID]
	out := make([]*types.EntraDeviceAuthMapping, 0, len(inner))
	for _, v := range inner {
		out = append(out, v)
	}
	return out, nil
}

func (m *MemoryStore) GetEntraDeviceMapping(_ context.Context, accountID, mappingID string) (*types.EntraDeviceAuthMapping, error) {
	if inner, ok := m.mappings[accountID]; ok {
		if mp, ok := inner[mappingID]; ok {
			return mp, nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) SaveEntraDeviceMapping(_ context.Context, mapping *types.EntraDeviceAuthMapping) error {
	inner := m.mappings[mapping.AccountID]
	if inner == nil {
		inner = map[string]*types.EntraDeviceAuthMapping{}
		m.mappings[mapping.AccountID] = inner
	}
	inner[mapping.ID] = mapping
	return nil
}

func (m *MemoryStore) DeleteEntraDeviceMapping(_ context.Context, accountID, mappingID string) error {
	if inner, ok := m.mappings[accountID]; ok {
		delete(inner, mappingID)
	}
	return nil
}

// --- bootstrap tokens ---

func (m *MemoryStore) StoreBootstrapToken(_ context.Context, peerID, token string) error {
	m.tokens[peerID] = token
	return nil
}

func (m *MemoryStore) ConsumeBootstrapToken(_ context.Context, peerID, token string) (bool, error) {
	got, ok := m.tokens[peerID]
	if !ok || got != token {
		return false, nil
	}
	delete(m.tokens, peerID)
	return true, nil
}
