package instance

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
)

// Manager handles instance-level operations like initial setup.
type Manager interface {
	// IsSetupRequired checks if instance setup is required.
	// Returns true if embedded IDP is enabled and no accounts exist.
	IsSetupRequired(ctx context.Context) (bool, error)

	// CreateOwnerUser creates the initial owner user in the embedded IDP.
	// This should only be called when IsSetupRequired returns true.
	CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error)
}

// DefaultManager is the default implementation of Manager.
type DefaultManager struct {
	store              store.Store
	embeddedIdpManager *idp.EmbeddedIdPManager
}

// NewManager creates a new instance manager.
// If idpManager is not an EmbeddedIdPManager, setup-related operations will return appropriate defaults.
func NewManager(store store.Store, idpManager idp.Manager) Manager {
	embeddedIdp, _ := idpManager.(*idp.EmbeddedIdPManager)

	return &DefaultManager{
		store:              store,
		embeddedIdpManager: embeddedIdp,
	}
}

// IsSetupRequired checks if instance setup is required.
// Setup is required when:
// 1. Embedded IDP is enabled
// 2. No accounts exist in the store
func (m *DefaultManager) IsSetupRequired(ctx context.Context) (bool, error) {
	// If embedded IDP is not enabled, setup is not required
	if m.embeddedIdpManager == nil {
		return false, nil
	}

	// Check if any accounts exist
	count, err := m.store.GetAccountsCounter(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get accounts count: %w", err)
	}

	// Setup is required if no accounts exist
	return count == 0, nil
}

// CreateOwnerUser creates the initial owner user in the embedded IDP.
func (m *DefaultManager) CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error) {
	if m.embeddedIdpManager == nil {
		return nil, errors.New("embedded IDP is not enabled")
	}

	userData, err := m.embeddedIdpManager.CreateUserWithPassword(ctx, email, password, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in embedded IdP: %w", err)
	}

	log.WithContext(ctx).Infof("created owner user %s in embedded IdP", email)

	return userData, nil
}
