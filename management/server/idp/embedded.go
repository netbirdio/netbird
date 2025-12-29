package idp

import (
	"context"
	"errors"
	"fmt"

	"github.com/dexidp/dex/storage"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

// Compile-time check that EmbeddedIdPManager implements Manager interface
var _ Manager = (*EmbeddedIdPManager)(nil)

// EmbeddedIdPManager implements the Manager interface using the embedded Dex IdP.
type EmbeddedIdPManager struct {
	provider   *dex.Provider
	appMetrics telemetry.AppMetrics
}

// NewEmbeddedIdPManager creates a new instance of EmbeddedIdPManager with an existing provider.
func NewEmbeddedIdPManager(provider *dex.Provider, appMetrics telemetry.AppMetrics) (*EmbeddedIdPManager, error) {
	if provider == nil {
		return nil, fmt.Errorf("embedded IdP provider is required")
	}

	return &EmbeddedIdPManager{
		provider:   provider,
		appMetrics: appMetrics,
	}, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (m *EmbeddedIdPManager) UpdateUserAppMetadata(ctx context.Context, userID string, appMetadata AppMetadata) error {
	// TODO: implement
	return nil
}

// GetUserDataByID requests user data from the embedded IdP via user ID.
func (m *EmbeddedIdPManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	user, err := m.provider.GetUserByID(ctx, userID)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &UserData{
		Email:       user.Email,
		Name:        user.Username,
		ID:          user.UserID,
		AppMetadata: appMetadata,
	}, nil
}

// GetAccount returns all the users for a given account.
// Note: Embedded dex doesn't store account metadata, so this returns all users.
func (m *EmbeddedIdPManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	users, err := m.provider.ListUsers(ctx)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	result := make([]*UserData, 0, len(users))
	for _, user := range users {
		result = append(result, &UserData{
			Email: user.Email,
			Name:  user.Username,
			ID:    user.UserID,
			AppMetadata: AppMetadata{
				WTAccountID: accountID,
			},
		})
	}

	return result, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// Note: Embedded dex doesn't store account metadata, so all users are indexed under UnsetAccountID.
func (m *EmbeddedIdPManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	if m.appMetrics != nil {
		m.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	users, err := m.provider.ListUsers(ctx)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	indexedUsers := make(map[string][]*UserData)
	for _, user := range users {
		indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], &UserData{
			Email: user.Email,
			Name:  user.Username,
			ID:    user.UserID,
		})
	}

	return indexedUsers, nil
}

// CreateUser creates a new user in the embedded IdP.
func (m *EmbeddedIdPManager) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	if m.appMetrics != nil {
		m.appMetrics.IDPMetrics().CountCreateUser()
	}

	// Check if user already exists
	_, err := m.provider.GetUser(ctx, email)
	if err == nil {
		return nil, fmt.Errorf("user with email %s already exists", email)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Generate a random password for the new user
	password := GeneratePassword(16, 2, 2, 2)

	// Create the user via provider (handles hashing and ID generation)
	// The provider returns an encoded user ID in Dex's format (base64 protobuf with connector ID)
	userID, err := m.provider.CreateUser(ctx, email, name, password)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to create user in embedded IdP: %w", err)
	}

	log.WithContext(ctx).Debugf("created user %s in embedded IdP", email)

	return &UserData{
		Email:    email,
		Name:     name,
		ID:       userID,
		Password: password,
		AppMetadata: AppMetadata{
			WTAccountID: accountID,
			WTInvitedBy: invitedByEmail,
		},
	}, nil
}

// GetUserByEmail searches users with a given email.
func (m *EmbeddedIdPManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	user, err := m.provider.GetUser(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil // Return empty slice for not found
		}
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return []*UserData{
		{
			Email: user.Email,
			Name:  user.Username,
			ID:    user.UserID,
		},
	}, nil
}

// InviteUserByID resends an invitation to a user.
func (m *EmbeddedIdPManager) InviteUserByID(ctx context.Context, userID string) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}

// DeleteUser deletes a user from the embedded IdP by user ID.
func (m *EmbeddedIdPManager) DeleteUser(ctx context.Context, userID string) error {
	if m.appMetrics != nil {
		m.appMetrics.IDPMetrics().CountDeleteUser()
	}

	// Get user by ID to retrieve email (provider.DeleteUser requires email)
	user, err := m.provider.GetUserByID(ctx, userID)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return fmt.Errorf("failed to get user for deletion: %w", err)
	}

	err = m.provider.DeleteUser(ctx, user.Email)
	if err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return fmt.Errorf("failed to delete user from embedded IdP: %w", err)
	}

	log.WithContext(ctx).Debugf("deleted user %s from embedded IdP", user.Email)

	return nil
}

// CreateConnector creates a new identity provider connector in Dex.
// Returns the created connector config with the redirect URL populated.
func (m *EmbeddedIdPManager) CreateConnector(ctx context.Context, cfg *dex.ConnectorConfig) (*dex.ConnectorConfig, error) {
	return m.provider.CreateConnector(ctx, cfg)
}

// GetConnector retrieves an identity provider connector by ID.
func (m *EmbeddedIdPManager) GetConnector(ctx context.Context, id string) (*dex.ConnectorConfig, error) {
	return m.provider.GetConnector(ctx, id)
}

// ListConnectors returns all identity provider connectors.
func (m *EmbeddedIdPManager) ListConnectors(ctx context.Context) ([]*dex.ConnectorConfig, error) {
	return m.provider.ListConnectors(ctx)
}

// UpdateConnector updates an existing identity provider connector.
func (m *EmbeddedIdPManager) UpdateConnector(ctx context.Context, cfg *dex.ConnectorConfig) error {
	return m.provider.UpdateConnector(ctx, cfg)
}

// DeleteConnector removes an identity provider connector.
func (m *EmbeddedIdPManager) DeleteConnector(ctx context.Context, id string) error {
	return m.provider.DeleteConnector(ctx, id)
}

// GetRedirectURI returns the Dex callback redirect URI for configuring connectors.
func (m *EmbeddedIdPManager) GetRedirectURI() string {
	return m.provider.GetRedirectURI()
}
