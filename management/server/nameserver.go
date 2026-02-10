package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/rs/xid"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	nbdomain "github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

var errInvalidDomainName = errors.New("invalid domain name")

// GetNameServerGroup gets a nameserver group object from account and nameserver group IDs
func (am *DefaultAccountManager) GetNameServerGroup(ctx context.Context, accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Nameservers, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetNameServerGroupByID(ctx, store.LockingStrengthNone, accountID, nsGroupID)
}

// CreateNameServerGroup creates and saves a new nameserver group
func (am *DefaultAccountManager) CreateNameServerGroup(ctx context.Context, accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainEnabled bool) (*nbdns.NameServerGroup, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Nameservers, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	newNSGroup := &nbdns.NameServerGroup{
		ID:                   xid.New().String(),
		AccountID:            accountID,
		Name:                 name,
		Description:          description,
		NameServers:          nameServerList,
		Groups:               groups,
		Enabled:              enabled,
		Primary:              primary,
		Domains:              domains,
		SearchDomainsEnabled: searchDomainEnabled,
	}

	var updateAccountPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateNameServerGroup(ctx, transaction, accountID, newNSGroup); err != nil {
			return err
		}

		updateAccountPeers, err = anyGroupHasPeersOrResources(ctx, transaction, accountID, newNSGroup.Groups)
		if err != nil {
			return err
		}

		if err = transaction.SaveNameServerGroup(ctx, newNSGroup); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, newNSGroup.ID, accountID, activity.NameserverGroupCreated, newNSGroup.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return newNSGroup.Copy(), nil
}

// SaveNameServerGroup saves nameserver group
func (am *DefaultAccountManager) SaveNameServerGroup(ctx context.Context, accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error {
	if nsGroupToSave == nil {
		return status.Errorf(status.InvalidArgument, "nameserver group provided is nil")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Nameservers, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var updateAccountPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		oldNSGroup, err := transaction.GetNameServerGroupByID(ctx, store.LockingStrengthNone, accountID, nsGroupToSave.ID)
		if err != nil {
			return err
		}
		nsGroupToSave.AccountID = accountID

		if err = validateNameServerGroup(ctx, transaction, accountID, nsGroupToSave); err != nil {
			return err
		}

		updateAccountPeers, err = areNameServerGroupChangesAffectPeers(ctx, transaction, nsGroupToSave, oldNSGroup)
		if err != nil {
			return err
		}

		if err = transaction.SaveNameServerGroup(ctx, nsGroupToSave); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, nsGroupToSave.ID, accountID, activity.NameserverGroupUpdated, nsGroupToSave.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// DeleteNameServerGroup deletes nameserver group with nsGroupID
func (am *DefaultAccountManager) DeleteNameServerGroup(ctx context.Context, accountID, nsGroupID, userID string) error {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Nameservers, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var nsGroup *nbdns.NameServerGroup
	var updateAccountPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		nsGroup, err = transaction.GetNameServerGroupByID(ctx, store.LockingStrengthUpdate, accountID, nsGroupID)
		if err != nil {
			return err
		}

		updateAccountPeers, err = anyGroupHasPeersOrResources(ctx, transaction, accountID, nsGroup.Groups)
		if err != nil {
			return err
		}

		if err = transaction.DeleteNameServerGroup(ctx, accountID, nsGroupID); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, nsGroup.ID, accountID, activity.NameserverGroupDeleted, nsGroup.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// ListNameServerGroups returns a list of nameserver groups from account
func (am *DefaultAccountManager) ListNameServerGroups(ctx context.Context, accountID string, userID string) ([]*nbdns.NameServerGroup, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Nameservers, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID)
}

func validateNameServerGroup(ctx context.Context, transaction store.Store, accountID string, nameserverGroup *nbdns.NameServerGroup) error {
	err := validateDomainInput(nameserverGroup.Primary, nameserverGroup.Domains, nameserverGroup.SearchDomainsEnabled)
	if err != nil {
		return err
	}

	err = validateNSList(nameserverGroup.NameServers)
	if err != nil {
		return err
	}

	nsServerGroups, err := transaction.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}

	err = validateNSGroupName(nameserverGroup.Name, nameserverGroup.ID, nsServerGroups)
	if err != nil {
		return err
	}

	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, nameserverGroup.Groups)
	if err != nil {
		return err
	}

	return validateGroups(nameserverGroup.Groups, groups)
}

// areNameServerGroupChangesAffectPeers checks if the changes in the nameserver group affect the peers.
func areNameServerGroupChangesAffectPeers(ctx context.Context, transaction store.Store, newNSGroup, oldNSGroup *nbdns.NameServerGroup) (bool, error) {
	if !newNSGroup.Enabled && !oldNSGroup.Enabled {
		return false, nil
	}

	hasPeers, err := anyGroupHasPeersOrResources(ctx, transaction, newNSGroup.AccountID, newNSGroup.Groups)
	if err != nil {
		return false, err
	}

	if hasPeers {
		return true, nil
	}

	return anyGroupHasPeersOrResources(ctx, transaction, oldNSGroup.AccountID, oldNSGroup.Groups)
}

func validateDomainInput(primary bool, domains []string, searchDomainsEnabled bool) error {
	if !primary && len(domains) == 0 {
		return status.Errorf(status.InvalidArgument, "nameserver group primary status is false and domains are empty,"+
			" it should be primary or have at least one domain")
	}
	if primary && len(domains) != 0 {
		return status.Errorf(status.InvalidArgument, "nameserver group primary status is true and domains are not empty,"+
			" you should set either primary or domain")
	}

	if primary && searchDomainsEnabled {
		return status.Errorf(status.InvalidArgument, "nameserver group primary status is true and search domains is enabled,"+
			" you should not set search domains for primary nameservers")
	}

	for _, domain := range domains {
		if err := validateDomain(domain); err != nil {
			return status.Errorf(status.InvalidArgument, "nameserver group got an invalid domain: %s %q", domain, err)
		}
	}
	return nil
}

func validateNSGroupName(name, nsGroupID string, groups []*nbdns.NameServerGroup) error {
	if utf8.RuneCountInString(name) > nbdns.MaxGroupNameChar || name == "" {
		return status.Errorf(status.InvalidArgument, "nameserver group name should be between 1 and %d", nbdns.MaxGroupNameChar)
	}

	for _, nsGroup := range groups {
		if name == nsGroup.Name && nsGroup.ID != nsGroupID {
			return status.Errorf(status.InvalidArgument, "nameserver group with name %s already exist", name)
		}
	}

	return nil
}

func validateNSList(list []nbdns.NameServer) error {
	nsListLength := len(list)
	if nsListLength == 0 || nsListLength > 3 {
		return status.Errorf(status.InvalidArgument, "the list of nameservers should be 1 or 3, got %d", len(list))
	}
	return nil
}

func validateGroups(list []string, groups map[string]*types.Group) error {
	if len(list) == 0 {
		return status.Errorf(status.InvalidArgument, "the list of group IDs should not be empty")
	}

	for _, id := range list {
		if id == "" {
			return status.Errorf(status.InvalidArgument, "group ID should not be empty string")
		}
		if _, found := groups[id]; !found {
			return status.Errorf(status.InvalidArgument, "group id %s not found", id)
		}
	}

	return nil
}

// validateDomain validates a nameserver match domain.
// Converts unicode to punycode. Wildcards are not allowed for nameservers.
func validateDomain(d string) error {
	if strings.HasPrefix(d, "*.") {
		return errors.New("wildcards not allowed")
	}

	// Nameservers allow trailing dot (FQDN format)
	toValidate := strings.TrimSuffix(d, ".")

	if _, err := nbdomain.ValidateDomains([]string{toValidate}); err != nil {
		return fmt.Errorf("%w: %w", errInvalidDomainName, err)
	}

	return nil
}
