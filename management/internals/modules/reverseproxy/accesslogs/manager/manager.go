package manager

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	geo                geolocation.Geolocation
}

func NewManager(store store.Store, permissionsManager permissions.Manager, geo geolocation.Geolocation) accesslogs.Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		geo:                geo,
	}
}

// SaveAccessLog saves an access log entry to the database after enriching it
func (m *managerImpl) SaveAccessLog(ctx context.Context, logEntry *accesslogs.AccessLogEntry) error {
	if m.geo != nil && logEntry.GeoLocation.ConnectionIP != nil {
		location, err := m.geo.Lookup(logEntry.GeoLocation.ConnectionIP)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to get location for access log source IP [%s]: %v", logEntry.GeoLocation.ConnectionIP.String(), err)
		} else {
			logEntry.GeoLocation.CountryCode = location.Country.ISOCode
			logEntry.GeoLocation.CityName = location.City.Names.En
			logEntry.GeoLocation.GeoNameID = location.City.GeonameID
		}
	}

	if err := m.store.CreateAccessLog(ctx, logEntry); err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"service_id": logEntry.ServiceID,
			"method":     logEntry.Method,
			"host":       logEntry.Host,
			"path":       logEntry.Path,
			"status":     logEntry.StatusCode,
		}).Errorf("failed to save access log: %v", err)
		return err
	}

	return nil
}

// GetAllAccessLogs retrieves access logs for an account with pagination and filtering
func (m *managerImpl) GetAllAccessLogs(ctx context.Context, accountID, userID string, filter *accesslogs.AccessLogFilter) ([]*accesslogs.AccessLogEntry, int64, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, 0, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, 0, status.NewPermissionDeniedError()
	}

	if err := m.resolveUserFilters(ctx, accountID, filter); err != nil {
		log.WithContext(ctx).Warnf("failed to resolve user filters: %v", err)
	}

	logs, totalCount, err := m.store.GetAccountAccessLogs(ctx, store.LockingStrengthNone, accountID, *filter)
	if err != nil {
		return nil, 0, err
	}

	return logs, totalCount, nil
}

// resolveUserFilters converts user email/name filters to user ID filter
func (m *managerImpl) resolveUserFilters(ctx context.Context, accountID string, filter *accesslogs.AccessLogFilter) error {
	if filter.UserEmail == nil && filter.UserName == nil {
		return nil
	}

	users, err := m.store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}

	var matchingUserIDs []string
	for _, user := range users {
		if filter.UserEmail != nil && strings.Contains(strings.ToLower(user.Email), strings.ToLower(*filter.UserEmail)) {
			matchingUserIDs = append(matchingUserIDs, user.Id)
			continue
		}
		if filter.UserName != nil && strings.Contains(strings.ToLower(user.Name), strings.ToLower(*filter.UserName)) {
			matchingUserIDs = append(matchingUserIDs, user.Id)
		}
	}

	if len(matchingUserIDs) > 0 {
		filter.UserID = &matchingUserIDs[0]
	}

	return nil
}
