package manager

import (
	"context"

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
			"proxy_id": logEntry.ProxyID,
			"method":   logEntry.Method,
			"host":     logEntry.Host,
			"path":     logEntry.Path,
			"status":   logEntry.StatusCode,
		}).Errorf("failed to save access log: %v", err)
		return err
	}

	return nil
}

// GetAllAccessLogs retrieves all access logs for an account
func (m *managerImpl) GetAllAccessLogs(ctx context.Context, accountID, userID string) ([]*accesslogs.AccessLogEntry, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Services, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	logs, err := m.store.GetAccountAccessLogs(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	return logs, nil
}
