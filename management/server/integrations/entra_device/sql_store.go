package entra_device

import (
	"context"
	"errors"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/types"
)

// SQLStore is a gorm-backed implementation of Store. It persists the
// integration config + mappings into the main management DB, and keeps
// short-lived bootstrap tokens in memory (they're meant to be consumed within
// minutes of enrolment).
type SQLStore struct {
	DB *gorm.DB

	// BootstrapTTL controls how long a bootstrap token remains valid.
	BootstrapTTL time.Duration

	mu       sync.Mutex
	tokens   map[string]bootstrapEntry
	tokenOps int
}

type bootstrapEntry struct {
	token     string
	expiresAt time.Time
}

// DefaultBootstrapTTL is how long a bootstrap token survives by default.
const DefaultBootstrapTTL = 5 * time.Minute

// NewSQLStore registers the gorm models and returns a ready Store.
// It is safe to call multiple times; AutoMigrate is idempotent.
func NewSQLStore(db *gorm.DB) (*SQLStore, error) {
	if err := db.AutoMigrate(&types.EntraDeviceAuth{}, &types.EntraDeviceAuthMapping{}); err != nil {
		return nil, err
	}
	return &SQLStore{
		DB:           db,
		BootstrapTTL: DefaultBootstrapTTL,
		tokens:       map[string]bootstrapEntry{},
	}, nil
}

// --- integration ---

// GetEntraDeviceAuth returns the account's integration or (nil, nil) when it
// doesn't exist.
func (s *SQLStore) GetEntraDeviceAuth(ctx context.Context, accountID string) (*types.EntraDeviceAuth, error) {
	var out types.EntraDeviceAuth
	err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).First(&out).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

// GetEntraDeviceAuthByTenant returns the integration registered for the given
// tenant ID (there can be at most one per tenant in this design).
func (s *SQLStore) GetEntraDeviceAuthByTenant(ctx context.Context, tenantID string) (*types.EntraDeviceAuth, error) {
	var out types.EntraDeviceAuth
	err := s.DB.WithContext(ctx).Where("tenant_id = ?", tenantID).First(&out).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

// SaveEntraDeviceAuth upserts the integration for an account.
func (s *SQLStore) SaveEntraDeviceAuth(ctx context.Context, auth *types.EntraDeviceAuth) error {
	return s.DB.WithContext(ctx).Save(auth).Error
}

// DeleteEntraDeviceAuth removes the integration and all its mappings for the
// given account.
func (s *SQLStore) DeleteEntraDeviceAuth(ctx context.Context, accountID string) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ?", accountID).Delete(&types.EntraDeviceAuthMapping{}).Error; err != nil {
			return err
		}
		return tx.Where("account_id = ?", accountID).Delete(&types.EntraDeviceAuth{}).Error
	})
}

// --- mappings ---

// ListEntraDeviceMappings returns all mappings for the account.
func (s *SQLStore) ListEntraDeviceMappings(ctx context.Context, accountID string) ([]*types.EntraDeviceAuthMapping, error) {
	var out []*types.EntraDeviceAuthMapping
	err := s.DB.WithContext(ctx).Where("account_id = ?", accountID).Order("priority ASC, id ASC").Find(&out).Error
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetEntraDeviceMapping returns a specific mapping by ID.
func (s *SQLStore) GetEntraDeviceMapping(ctx context.Context, accountID, mappingID string) (*types.EntraDeviceAuthMapping, error) {
	var out types.EntraDeviceAuthMapping
	err := s.DB.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, mappingID).First(&out).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

// SaveEntraDeviceMapping upserts a mapping row.
func (s *SQLStore) SaveEntraDeviceMapping(ctx context.Context, mapping *types.EntraDeviceAuthMapping) error {
	return s.DB.WithContext(ctx).Save(mapping).Error
}

// DeleteEntraDeviceMapping removes a mapping by ID.
func (s *SQLStore) DeleteEntraDeviceMapping(ctx context.Context, accountID, mappingID string) error {
	return s.DB.WithContext(ctx).
		Where("account_id = ? AND id = ?", accountID, mappingID).
		Delete(&types.EntraDeviceAuthMapping{}).Error
}

// --- bootstrap tokens (in-memory, short-lived) ---

// StoreBootstrapToken stores a short-lived (BootstrapTTL) bootstrap token for
// the given peer ID. Calling StoreBootstrapToken for the same peer ID replaces
// any existing token.
func (s *SQLStore) StoreBootstrapToken(_ context.Context, peerID, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ttl := s.BootstrapTTL
	if ttl <= 0 {
		ttl = DefaultBootstrapTTL
	}
	s.tokens[peerID] = bootstrapEntry{
		token:     token,
		expiresAt: time.Now().UTC().Add(ttl),
	}
	s.tokenOps++
	if s.tokenOps%64 == 0 {
		s.gcTokensLocked(time.Now().UTC())
	}
	return nil
}

// ConsumeBootstrapToken returns (true, nil) on success, (false, nil) if the
// token doesn't match or has expired. Tokens are consumed exactly once.
func (s *SQLStore) ConsumeBootstrapToken(_ context.Context, peerID, token string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.tokens[peerID]
	if !ok {
		return false, nil
	}
	delete(s.tokens, peerID)
	if entry.token != token {
		return false, nil
	}
	if time.Now().UTC().After(entry.expiresAt) {
		return false, nil
	}
	return true, nil
}

func (s *SQLStore) gcTokensLocked(now time.Time) {
	for k, v := range s.tokens {
		if now.After(v.expiresAt) {
			delete(s.tokens, k)
		}
	}
}
