package manager

import (
	"context"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// AutoCreateForService creates a NetBird DNS A record auto-managed by the
// given reverse-proxy service. It is intended to be called from inside an
// active store transaction (e.g., the service manager's CreateService or
// UpdateService transaction).
//
// Semantics:
//   - Locates the matching zone in the account by longest-suffix match on
//     fqdn against zone.Domain. Returns InvalidArgument if none found.
//   - Refuses to create if any record at the same name exists with a
//     ManagedByServiceID different from serviceID, or with no manager at all.
//   - Issues IncrementNetworkSerial after the create so the network map
//     update propagates to peers. The caller is responsible for the
//     post-commit UpdateAccountPeers broadcast.
func AutoCreateForService(
	ctx context.Context,
	tx store.Store,
	accountID, serviceID, fqdn string,
	ip net.IP,
) (*records.Record, error) {
	if accountID == "" || serviceID == "" || fqdn == "" || ip == nil {
		return nil, status.Errorf(status.InvalidArgument,
			"AutoCreateForService: accountID, serviceID, fqdn, and ip are required")
	}

	zone, err := findZoneForFQDN(ctx, tx, accountID, fqdn)
	if err != nil {
		return nil, err
	}

	recordType := records.RecordTypeA
	if ip.To4() == nil {
		recordType = records.RecordTypeAAAA
	}

	rec := records.NewRecord(accountID, zone.ID, fqdn, recordType, ip.String(), 300)
	rec.ManagedByServiceID = serviceID

	if err := validateAutoConflicts(ctx, tx, zone, rec, serviceID); err != nil {
		return nil, err
	}

	if err := tx.CreateDNSRecord(ctx, rec); err != nil {
		return nil, fmt.Errorf("create auto dns record: %w", err)
	}
	if err := tx.IncrementNetworkSerial(ctx, accountID); err != nil {
		return nil, fmt.Errorf("increment network serial: %w", err)
	}
	log.WithContext(ctx).WithFields(log.Fields{
		"account_id": accountID,
		"service_id": serviceID,
		"domain":     fqdn,
		"record_id":  rec.ID,
		"zone_id":    rec.ZoneID,
		"action":     "auto_dns_create",
	}).Info("auto-created managed DNS record for private service")
	return rec, nil
}

// AutoUpdateForService is delete-old-by-serviceID then create-new within
// the same transaction. Used when a private service's domain or proxy
// cluster changes.
func AutoUpdateForService(
	ctx context.Context,
	tx store.Store,
	accountID, serviceID, fqdn string,
	ip net.IP,
) (*records.Record, error) {
	if err := AutoDeleteForService(ctx, tx, accountID, serviceID); err != nil {
		return nil, err
	}
	return AutoCreateForService(ctx, tx, accountID, serviceID, fqdn, ip)
}

// AutoDeleteForService removes any record (in any zone within the account)
// where ManagedByServiceID == serviceID. Idempotent: returns nil if none
// exist.
func AutoDeleteForService(
	ctx context.Context,
	tx store.Store,
	accountID, serviceID string,
) error {
	if accountID == "" || serviceID == "" {
		return status.Errorf(status.InvalidArgument,
			"AutoDeleteForService: accountID and serviceID are required")
	}

	zs, err := tx.GetAccountZones(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return fmt.Errorf("get account zones: %w", err)
	}

	deleted := 0
	for _, z := range zs {
		for _, r := range z.Records {
			if r.ManagedByServiceID != serviceID {
				continue
			}
			if err := tx.DeleteDNSRecord(ctx, accountID, z.ID, r.ID); err != nil {
				return fmt.Errorf("delete auto dns record %s: %w", r.ID, err)
			}
			deleted++
		}
	}

	if deleted > 0 {
		if err := tx.IncrementNetworkSerial(ctx, accountID); err != nil {
			return fmt.Errorf("increment network serial: %w", err)
		}
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id": accountID,
			"service_id": serviceID,
			"deleted":    deleted,
			"action":     "auto_dns_delete",
		}).Info("removed managed DNS records for private service")
	}
	return nil
}

// findZoneForFQDN returns the account's zone that best matches the FQDN by
// longest-suffix match on zone.Domain. Returns InvalidArgument with a clear
// remediation message when no zone applies.
func findZoneForFQDN(ctx context.Context, tx store.Store, accountID, fqdn string) (*zones.Zone, error) {
	zs, err := tx.GetAccountZones(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account zones: %w", err)
	}
	var best *zones.Zone
	for _, z := range zs {
		if fqdn == z.Domain || strings.HasSuffix(fqdn, "."+z.Domain) {
			if best == nil || len(z.Domain) > len(best.Domain) {
				best = z
			}
		}
	}
	if best == nil {
		return nil, status.Errorf(status.InvalidArgument,
			"no DNS zone configured for parent of %q in your account; create a zone for the parent domain in the DNS Zones page before enabling Private mode",
			fqdn)
	}
	return best, nil
}

// validateAutoConflicts enforces that an auto-managed record may only be
// created at an FQDN that has no existing record other than (optionally)
// one already owned by the same service. User-managed records at the same
// name produce a clear error pointing the user to remove their manual
// record before enabling Private mode.
func validateAutoConflicts(ctx context.Context, tx store.Store, zone *zones.Zone, rec *records.Record, serviceID string) error {
	if rec.Name != zone.Domain && !strings.HasSuffix(rec.Name, "."+zone.Domain) {
		return status.Errorf(status.InvalidArgument,
			"record name %q does not belong to zone %q", rec.Name, zone.Domain)
	}
	existing, err := tx.GetZoneDNSRecordsByName(ctx, store.LockingStrengthNone, zone.AccountID, zone.ID, rec.Name)
	if err != nil {
		return fmt.Errorf("check existing records: %w", err)
	}
	for _, e := range existing {
		if e.ManagedByServiceID == serviceID {
			continue
		}
		if e.ManagedByServiceID == "" {
			return status.Errorf(status.AlreadyExists,
				"a user-managed DNS record for %q already exists in your account; remove it before enabling Private mode for this service",
				rec.Name)
		}
		return status.Errorf(status.AlreadyExists,
			"a DNS record for %q is already managed by another service (%s)",
			rec.Name, e.ManagedByServiceID)
	}
	return nil
}
