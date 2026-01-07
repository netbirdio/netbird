package instance

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
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

	setupRequired bool
	setupMu       sync.RWMutex
}

// NewManager creates a new instance manager.
// If idpManager is not an EmbeddedIdPManager, setup-related operations will return appropriate defaults.
func NewManager(ctx context.Context, store store.Store, idpManager idp.Manager) (Manager, error) {
	embeddedIdp, _ := idpManager.(*idp.EmbeddedIdPManager)

	m := &DefaultManager{
		store:              store,
		embeddedIdpManager: embeddedIdp,
		setupRequired:      false,
	}

	if embeddedIdp != nil {
		err := m.loadSetupRequired(ctx)
		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (m *DefaultManager) loadSetupRequired(ctx context.Context) error {
	users, err := m.embeddedIdpManager.GetAllAccounts(ctx)
	if err != nil {
		return err
	}

	m.setupMu.Lock()
	m.setupRequired = len(users) == 0
	m.setupMu.Unlock()

	return nil
}

// IsSetupRequired checks if instance setup is required.
// Setup is required when:
// 1. Embedded IDP is enabled
// 2. No accounts exist in the store
func (m *DefaultManager) IsSetupRequired(_ context.Context) (bool, error) {
	if m.embeddedIdpManager == nil {
		return false, nil
	}

	m.setupMu.RLock()
	defer m.setupMu.RUnlock()

	return m.setupRequired, nil
}

// CreateOwnerUser creates the initial owner user in the embedded IDP.
func (m *DefaultManager) CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error) {

	if err := m.validateSetupInfo(email, password, name); err != nil {
		return nil, err
	}

	if m.embeddedIdpManager == nil {
		return nil, errors.New("embedded IDP is not enabled")
	}

	m.setupMu.RLock()
	setupRequired := m.setupRequired
	m.setupMu.RUnlock()

	if !setupRequired {
		return nil, status.Errorf(status.PreconditionFailed, "setup already completed")
	}

	userData, err := m.embeddedIdpManager.CreateUserWithPassword(ctx, email, password, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in embedded IdP: %w", err)
	}

	m.setupMu.Lock()
	m.setupRequired = false
	m.setupMu.Unlock()

	log.WithContext(ctx).Infof("created owner user %s in embedded IdP", email)

	return userData, nil
}

func (m *DefaultManager) validateSetupInfo(email, password, name string) error {
	if email == "" {
		return status.Errorf(status.InvalidArgument, "email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid email format")
	}
	if name == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}
	if password == "" {
		return status.Errorf(status.InvalidArgument, "password is required")
	}
	if len(password) < 8 {
		return status.Errorf(status.InvalidArgument, "password must be at least 8 characters")
	}
	return nil
}
