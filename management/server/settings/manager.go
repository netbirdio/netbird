package settings

//go:generate go run github.com/golang/mock/mockgen -package settings -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integrations/extra_settings"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
)

type Manager interface {
	GetExtraSettingsManager() extra_settings.Manager
	GetSettings(ctx context.Context, accountID string, userID string) (*types.Settings, error)
	GetExtraSettings(ctx context.Context, accountID string) (*types.ExtraSettings, error)
	UpdateExtraSettings(ctx context.Context, accountID, userID string, extraSettings *types.ExtraSettings) (bool, error)
}

type managerImpl struct {
	store                store.Store
	extraSettingsManager extra_settings.Manager
	userManager          users.Manager
}

func NewManager(store store.Store, userManager users.Manager, extraSettingsManager extra_settings.Manager) Manager {
	return &managerImpl{
		store:                store,
		extraSettingsManager: extraSettingsManager,
		userManager:          userManager,
	}
}

func (m *managerImpl) GetExtraSettingsManager() extra_settings.Manager {
	return m.extraSettingsManager
}

func (m *managerImpl) GetSettings(ctx context.Context, accountID, userID string) (*types.Settings, error) {
	if userID != activity.SystemInitiator {
		user, err := m.userManager.GetUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("get user: %w", err)
		}

		if user.AccountID != accountID || (!user.HasAdminPower() && !user.IsServiceUser) {
			return nil, status.Errorf(status.PermissionDenied, "the user has no permission to access account data")
		}
	}

	extraSettings, err := m.extraSettingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get extra settings: %w", err)
	}

	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account settings: %w", err)
	}

	// Once we migrate the peer approval to settings manager this merging is obsolete
	if settings.Extra != nil {
		settings.Extra.FlowEnabled = extraSettings.FlowEnabled
		settings.Extra.FlowPacketCounterEnabled = extraSettings.FlowPacketCounterEnabled
		settings.Extra.FlowENCollectionEnabled = extraSettings.FlowENCollectionEnabled
		settings.Extra.FlowDnsCollectionEnabled = extraSettings.FlowDnsCollectionEnabled
	}

	return settings, nil
}

func (m *managerImpl) GetExtraSettings(ctx context.Context, accountID string) (*types.ExtraSettings, error) {
	extraSettings, err := m.extraSettingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get extra settings: %w", err)
	}

	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account settings: %w", err)
	}

	// Once we migrate the peer approval to settings manager this merging is obsolete
	if settings.Extra == nil {
		settings.Extra = &types.ExtraSettings{}
	}

	settings.Extra.FlowEnabled = extraSettings.FlowEnabled

	return settings.Extra, nil
}

func (m *managerImpl) UpdateExtraSettings(ctx context.Context, accountID, userID string, extraSettings *types.ExtraSettings) (bool, error) {
	return m.extraSettingsManager.UpdateExtraSettings(ctx, accountID, userID, extraSettings)
}
