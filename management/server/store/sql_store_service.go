package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/status"
)

// serviceSelectColumns and targetSelectColumns are the column lists the Postgres
// pgx read path scans. They must stay in sync with the rpservice.Service and
// rpservice.Target gorm models; TestPgxServiceColumnsMatchGorm enforces this.
const serviceSelectColumns = `id, account_id, name, domain, enabled, auth, restrictions,
	meta_created_at, meta_certificate_issued_at, meta_last_renewed_at, meta_status, proxy_cluster,
	pass_host_header, rewrite_redirects, session_private_key, session_public_key,
	mode, listen_port, port_auto_assigned, source, source_peer, terminated,
	private, access_groups`

func (s *SqlStore) getServices(ctx context.Context, accountID string) ([]*rpservice.Service, error) {
	const serviceQuery = `SELECT ` + serviceSelectColumns + ` FROM services WHERE account_id = $1`

	serviceRows, err := s.pool.Query(ctx, serviceQuery, accountID)
	if err != nil {
		return nil, err
	}

	services, err := pgx.CollectRows(serviceRows, scanService)
	if err != nil {
		return nil, err
	}

	if len(services) == 0 {
		return services, nil
	}

	serviceIDs := make([]string, len(services))
	serviceMap := make(map[string]*rpservice.Service)
	for i, svc := range services {
		serviceIDs[i] = svc.ID
		serviceMap[svc.ID] = svc
	}

	targets, err := s.getServiceTargets(ctx, serviceIDs)
	if err != nil {
		return nil, err
	}

	for _, target := range targets {
		if service, ok := serviceMap[target.ServiceID]; ok {
			service.Targets = append(service.Targets, target)
		}
	}

	return services, nil
}

func scanService(row pgx.CollectableRow) (*rpservice.Service, error) {
	var s rpservice.Service
	var auth []byte
	var restrictions []byte
	var accessGroups []byte
	var createdAt, certIssuedAt, lastRenewedAt sql.NullTime
	var status, proxyCluster, sessionPrivateKey, sessionPublicKey sql.NullString
	var mode, source, sourcePeer sql.NullString
	var terminated, portAutoAssigned, private sql.NullBool
	var listenPort sql.NullInt64
	err := row.Scan(
		&s.ID,
		&s.AccountID,
		&s.Name,
		&s.Domain,
		&s.Enabled,
		&auth,
		&restrictions,
		&createdAt,
		&certIssuedAt,
		&lastRenewedAt,
		&status,
		&proxyCluster,
		&s.PassHostHeader,
		&s.RewriteRedirects,
		&sessionPrivateKey,
		&sessionPublicKey,
		&mode,
		&listenPort,
		&portAutoAssigned,
		&source,
		&sourcePeer,
		&terminated,
		&private,
		&accessGroups,
	)
	if err != nil {
		return nil, err
	}

	if auth != nil {
		if err := json.Unmarshal(auth, &s.Auth); err != nil {
			return nil, err
		}
	}

	if len(restrictions) > 0 {
		if err := json.Unmarshal(restrictions, &s.Restrictions); err != nil {
			return nil, fmt.Errorf("unmarshal restrictions: %w", err)
		}
	}

	if len(accessGroups) > 0 {
		if err := json.Unmarshal(accessGroups, &s.AccessGroups); err != nil {
			return nil, fmt.Errorf("unmarshal access_groups: %w", err)
		}
	}

	if private.Valid {
		s.Private = private.Bool
	}

	s.Meta = serviceMetaFromRow(createdAt, certIssuedAt, lastRenewedAt, status)
	if proxyCluster.Valid {
		s.ProxyCluster = proxyCluster.String
	}
	if sessionPrivateKey.Valid {
		s.SessionPrivateKey = sessionPrivateKey.String
	}
	if sessionPublicKey.Valid {
		s.SessionPublicKey = sessionPublicKey.String
	}
	if mode.Valid {
		s.Mode = mode.String
	}
	if source.Valid {
		s.Source = source.String
	}
	if sourcePeer.Valid {
		s.SourcePeer = sourcePeer.String
	}
	if terminated.Valid {
		s.Terminated = terminated.Bool
	}
	if portAutoAssigned.Valid {
		s.PortAutoAssigned = portAutoAssigned.Bool
	}
	if listenPort.Valid {
		if listenPort.Int64 < 0 || listenPort.Int64 > math.MaxUint16 {
			return nil, fmt.Errorf("listen_port %d out of range", listenPort.Int64)
		}
		s.ListenPort = uint16(listenPort.Int64)
	}
	s.Targets = []*rpservice.Target{}
	return &s, nil
}

func serviceMetaFromRow(createdAt, certIssuedAt, lastRenewedAt sql.NullTime, status sql.NullString) rpservice.Meta {
	meta := rpservice.Meta{}
	if createdAt.Valid {
		meta.CreatedAt = createdAt.Time
	}
	if certIssuedAt.Valid {
		t := certIssuedAt.Time
		meta.CertificateIssuedAt = &t
	}
	if lastRenewedAt.Valid {
		t := lastRenewedAt.Time
		meta.LastRenewedAt = &t
	}
	if status.Valid {
		meta.Status = status.String
	}
	return meta
}

func (s *SqlStore) CreateService(ctx context.Context, service *rpservice.Service) error {
	serviceCopy := service.Copy()
	if err := serviceCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		return fmt.Errorf("encrypt service data: %w", err)
	}
	result := s.db.Create(serviceCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create service to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to create service to store")
	}

	return nil
}

func (s *SqlStore) UpdateService(ctx context.Context, service *rpservice.Service) error {
	serviceCopy := service.Copy()
	if err := serviceCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		return fmt.Errorf("encrypt service data: %w", err)
	}

	// Create target type instance outside transaction to avoid variable shadowing
	targetType := &rpservice.Target{}

	// Use a transaction to ensure atomic updates of the service and its targets
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Delete existing targets
		if err := tx.Where("service_id = ?", serviceCopy.ID).Delete(targetType).Error; err != nil {
			return err
		}

		// Update the service and create new targets
		if err := tx.Session(&gorm.Session{FullSaveAssociations: true}).Save(serviceCopy).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to update service to store: %v", err)
		return status.Errorf(status.Internal, "failed to update service to store")
	}

	return nil
}

func (s *SqlStore) DeleteService(ctx context.Context, accountID, serviceID string) error {
	result := s.db.Delete(&rpservice.Service{}, accountAndIDQueryCondition, accountID, serviceID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete service from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete service from store")
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "service %s not found", serviceID)
	}

	return nil
}

func (s *SqlStore) GetServiceByID(ctx context.Context, lockStrength LockingStrength, accountID, serviceID string) (*rpservice.Service, error) {
	tx := s.db.Preload("Targets")
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var service *rpservice.Service
	result := tx.Take(&service, accountAndIDQueryCondition, accountID, serviceID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "service %s not found", serviceID)
		}

		log.WithContext(ctx).Errorf("failed to get service from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get service from store")
	}

	if err := service.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt service data: %w", err)
	}

	return service, nil
}

func (s *SqlStore) GetServiceByDomain(ctx context.Context, domain string) (*rpservice.Service, error) {
	var service *rpservice.Service
	result := s.db.Preload("Targets").Where("domain = ?", domain).First(&service)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "service with domain %s not found", domain)
		}

		log.WithContext(ctx).Errorf("failed to get service by domain from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get service by domain from store")
	}

	if err := service.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt service data: %w", err)
	}

	return service, nil
}

func (s *SqlStore) GetServices(ctx context.Context, lockStrength LockingStrength) ([]*rpservice.Service, error) {
	tx := s.db.Preload("Targets")
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var serviceList []*rpservice.Service
	result := tx.Find(&serviceList)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get services from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get services from store")
	}

	for _, service := range serviceList {
		if err := service.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt service data: %w", err)
		}
	}

	return serviceList, nil
}

func (s *SqlStore) GetAccountServices(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*rpservice.Service, error) {
	tx := s.db.Preload("Targets")
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var serviceList []*rpservice.Service
	result := tx.Find(&serviceList, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get services from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get services from store")
	}

	for _, service := range serviceList {
		if err := service.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt service data: %w", err)
		}
	}

	return serviceList, nil
}

// RenewEphemeralService updates the last_renewed_at timestamp for an ephemeral service.
func (s *SqlStore) RenewEphemeralService(ctx context.Context, accountID, peerID, serviceID string) error {
	result := s.db.Model(&rpservice.Service{}).
		Where("id = ? AND account_id = ? AND source_peer = ? AND source = ?", serviceID, accountID, peerID, rpservice.SourceEphemeral).
		Update("meta_last_renewed_at", time.Now())
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to renew ephemeral service: %v", result.Error)
		return status.Errorf(status.Internal, "renew ephemeral service")
	}
	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "no active expose session for service %s", serviceID)
	}
	return nil
}

// GetExpiredEphemeralServices returns ephemeral services whose last renewal exceeds the given TTL.
// Only the fields needed for reaping are selected. The limit parameter caps the batch size to
// avoid loading too many rows in a single tick. Rows with empty source_peer are excluded to
// skip malformed legacy data.
func (s *SqlStore) GetExpiredEphemeralServices(ctx context.Context, ttl time.Duration, limit int) ([]*rpservice.Service, error) {
	cutoff := time.Now().Add(-ttl)
	var services []*rpservice.Service
	result := s.db.
		Select("id", "account_id", "source_peer", "domain").
		Where("source = ? AND source_peer <> '' AND meta_last_renewed_at < ?", rpservice.SourceEphemeral, cutoff).
		Limit(limit).
		Find(&services)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get expired ephemeral services: %v", result.Error)
		return nil, status.Errorf(status.Internal, "get expired ephemeral services")
	}
	return services, nil
}

// CountEphemeralServicesByPeer returns the count of ephemeral services for a specific peer.
// Use LockingStrengthUpdate inside a transaction to serialize concurrent create operations.
// The locking is applied via a row-level SELECT ... FOR UPDATE (not on the aggregate) to
// stay compatible with Postgres, which disallows FOR UPDATE on COUNT(*).
func (s *SqlStore) CountEphemeralServicesByPeer(ctx context.Context, lockStrength LockingStrength, accountID, peerID string) (int64, error) {
	if lockStrength == LockingStrengthNone {
		var count int64
		result := s.db.Model(&rpservice.Service{}).
			Where("account_id = ? AND source_peer = ? AND source = ?", accountID, peerID, rpservice.SourceEphemeral).
			Count(&count)
		if result.Error != nil {
			log.WithContext(ctx).Errorf("failed to count ephemeral services: %v", result.Error)
			return 0, status.Errorf(status.Internal, "count ephemeral services")
		}
		return count, nil
	}

	var ids []string
	result := s.db.Model(&rpservice.Service{}).
		Clauses(clause.Locking{Strength: string(lockStrength)}).
		Select("id").
		Where("account_id = ? AND source_peer = ? AND source = ?", accountID, peerID, rpservice.SourceEphemeral).
		Pluck("id", &ids)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to count ephemeral services: %v", result.Error)
		return 0, status.Errorf(status.Internal, "count ephemeral services")
	}
	return int64(len(ids)), nil
}

// EphemeralServiceExists checks if an ephemeral service exists for the given peer and domain.
// Use LockingStrengthUpdate inside a transaction to serialize concurrent create operations.
func (s *SqlStore) EphemeralServiceExists(ctx context.Context, lockStrength LockingStrength, accountID, peerID, domain string) (bool, error) {
	if lockStrength == LockingStrengthNone {
		var count int64
		result := s.db.Model(&rpservice.Service{}).
			Where("account_id = ? AND source_peer = ? AND domain = ? AND source = ?", accountID, peerID, domain, rpservice.SourceEphemeral).
			Count(&count)
		if result.Error != nil {
			log.WithContext(ctx).Errorf("failed to check ephemeral service existence: %v", result.Error)
			return false, status.Errorf(status.Internal, "check ephemeral service existence")
		}
		return count > 0, nil
	}

	var id string
	result := s.db.Model(&rpservice.Service{}).
		Clauses(clause.Locking{Strength: string(lockStrength)}).
		Select("id").
		Where("account_id = ? AND source_peer = ? AND domain = ? AND source = ?", accountID, peerID, domain, rpservice.SourceEphemeral).
		Limit(1).
		Pluck("id", &id)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to check ephemeral service existence: %v", result.Error)
		return false, status.Errorf(status.Internal, "check ephemeral service existence")
	}
	return id != "", nil
}

// GetServicesByClusterAndPort returns services matching the given proxy cluster, mode, and listen port.
func (s *SqlStore) GetServicesByClusterAndPort(ctx context.Context, lockStrength LockingStrength, proxyCluster string, mode string, listenPort uint16) ([]*rpservice.Service, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var services []*rpservice.Service
	result := tx.Where("proxy_cluster = ? AND mode = ? AND listen_port = ?", proxyCluster, mode, listenPort).Find(&services)
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "query services by cluster and port")
	}

	return services, nil
}

// GetServicesByCluster returns all services for the given proxy cluster.
func (s *SqlStore) GetServicesByCluster(ctx context.Context, lockStrength LockingStrength, proxyCluster string) ([]*rpservice.Service, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var services []*rpservice.Service
	result := tx.Where("proxy_cluster = ?", proxyCluster).Find(&services)
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "query services by cluster")
	}
	return services, nil
}
