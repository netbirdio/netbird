package manager

import (
	"context"
	"strings"
	"time"

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
	cleanupCancel      context.CancelFunc
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

// CleanupOldAccessLogs deletes access logs older than the specified retention period
func (m *managerImpl) CleanupOldAccessLogs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		log.WithContext(ctx).Debug("access log cleanup skipped: retention days is 0 or negative")
		return 0, nil
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	deletedCount, err := m.store.DeleteOldAccessLogs(ctx, cutoffTime)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to cleanup old access logs: %v", err)
		return 0, err
	}

	if deletedCount > 0 {
		log.WithContext(ctx).Infof("cleaned up %d access logs older than %d days", deletedCount, retentionDays)
	}

	return deletedCount, nil
}

// StartPeriodicCleanup starts a background goroutine that periodically cleans up old access logs
func (m *managerImpl) StartPeriodicCleanup(ctx context.Context, retentionDays, cleanupIntervalHours int) {
	if retentionDays <= 0 {
		log.WithContext(ctx).Debug("periodic access log cleanup disabled: retention days is 0 or negative")
		return
	}

	if cleanupIntervalHours <= 0 {
		cleanupIntervalHours = 24
	}

	cleanupCtx, cancel := context.WithCancel(ctx)
	m.cleanupCancel = cancel

	cleanupInterval := time.Duration(cleanupIntervalHours) * time.Hour
	ticker := time.NewTicker(cleanupInterval)

	go func() {
		defer ticker.Stop()

		// Run cleanup immediately on startup
		log.WithContext(cleanupCtx).Infof("starting access log cleanup routine (retention: %d days, interval: %d hours)", retentionDays, cleanupIntervalHours)
		if _, err := m.CleanupOldAccessLogs(cleanupCtx, retentionDays); err != nil {
			log.WithContext(cleanupCtx).Errorf("initial access log cleanup failed: %v", err)
		}

		for {
			select {
			case <-cleanupCtx.Done():
				log.WithContext(cleanupCtx).Info("stopping access log cleanup routine")
				return
			case <-ticker.C:
				if _, err := m.CleanupOldAccessLogs(cleanupCtx, retentionDays); err != nil {
					log.WithContext(cleanupCtx).Errorf("periodic access log cleanup failed: %v", err)
				}
			}
		}
	}()
}

// StopPeriodicCleanup stops the periodic cleanup routine
func (m *managerImpl) StopPeriodicCleanup() {
	if m.cleanupCancel != nil {
		m.cleanupCancel()
	}
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
