package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/miekg/dns"
	"github.com/rs/xid"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/status"
)

const domainPattern = `^(?i)[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$`

// GetNameServerGroup gets a nameserver group object from account and nameserver group IDs
func (am *DefaultAccountManager) GetNameServerGroup(ctx context.Context, accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewUnauthorizedToViewNSGroupsError()
	}

	return am.Store.GetNameServerGroupByID(ctx, LockingStrengthShare, accountID, nsGroupID)
}

// CreateNameServerGroup creates and saves a new nameserver group
func (am *DefaultAccountManager) CreateNameServerGroup(ctx context.Context, accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainEnabled bool) (*nbdns.NameServerGroup, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
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

	err = am.validateNameServerGroup(ctx, accountID, newNSGroup)
	if err != nil {
		return nil, err
	}

	updateAccountPeers, err := am.anyGroupHasPeers(ctx, accountID, newNSGroup.Groups)
	if err != nil {
		return nil, err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		if err = transaction.SaveNameServerGroup(ctx, LockingStrengthUpdate, newNSGroup); err != nil {
			return fmt.Errorf("failed to create nameserver group: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, newNSGroup.ID, accountID, activity.NameserverGroupCreated, newNSGroup.EventMeta())

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return newNSGroup.Copy(), nil
}

// SaveNameServerGroup saves nameserver group
func (am *DefaultAccountManager) SaveNameServerGroup(ctx context.Context, accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error {
	if nsGroupToSave == nil {
		return status.Errorf(status.InvalidArgument, "nameserver group provided is nil")
	}

	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	oldNSGroup, err := am.Store.GetNameServerGroupByID(ctx, LockingStrengthShare, accountID, nsGroupToSave.ID)
	if err != nil {
		return err
	}

	if err = am.validateNameServerGroup(ctx, accountID, nsGroupToSave); err != nil {
		return err
	}

	updateAccountPeers, err := am.areNameServerGroupChangesAffectPeers(ctx, nsGroupToSave, oldNSGroup)
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		if err = transaction.SaveNameServerGroup(ctx, LockingStrengthUpdate, nsGroupToSave); err != nil {
			return fmt.Errorf("failed to update nameserver group: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, nsGroupToSave.ID, accountID, activity.NameserverGroupUpdated, nsGroupToSave.EventMeta())

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// DeleteNameServerGroup deletes nameserver group with nsGroupID
func (am *DefaultAccountManager) DeleteNameServerGroup(ctx context.Context, accountID, nsGroupID, userID string) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	nsGroup, err := am.Store.GetNameServerGroupByID(ctx, LockingStrengthShare, accountID, nsGroupID)
	if err != nil {
		return err
	}

	updateAccountPeers, err := am.anyGroupHasPeers(ctx, accountID, nsGroup.Groups)
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		if err = transaction.DeleteNameServerGroup(ctx, LockingStrengthUpdate, accountID, nsGroupID); err != nil {
			return fmt.Errorf("failed to delete nameserver group: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, nsGroup.ID, accountID, activity.NameserverGroupDeleted, nsGroup.EventMeta())

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// ListNameServerGroups returns a list of nameserver groups from account
func (am *DefaultAccountManager) ListNameServerGroups(ctx context.Context, accountID string, userID string) ([]*nbdns.NameServerGroup, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewUnauthorizedToViewNSGroupsError()
	}

	return am.Store.GetAccountNameServerGroups(ctx, LockingStrengthShare, accountID)
}

func (am *DefaultAccountManager) validateNameServerGroup(ctx context.Context, accountID string, nameserverGroup *nbdns.NameServerGroup) error {
	err := validateDomainInput(nameserverGroup.Primary, nameserverGroup.Domains, nameserverGroup.SearchDomainsEnabled)
	if err != nil {
		return err
	}

	err = validateNSList(nameserverGroup.NameServers)
	if err != nil {
		return err
	}

	nsServerGroups, err := am.Store.GetAccountNameServerGroups(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	err = validateNSGroupName(nameserverGroup.Name, nameserverGroup.ID, nsServerGroups)
	if err != nil {
		return err
	}

	groups, err := am.Store.GetAccountGroups(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	err = validateGroups(nameserverGroup.Groups, groups)
	if err != nil {
		return err
	}

	return nil
}

// areNameServerGroupChangesAffectPeers checks if the changes in the nameserver group affect the peers.
func (am *DefaultAccountManager) areNameServerGroupChangesAffectPeers(ctx context.Context, newNSGroup, oldNSGroup *nbdns.NameServerGroup) (bool, error) {
	if !newNSGroup.Enabled && !oldNSGroup.Enabled {
		return false, nil
	}

	hasPeers, err := am.anyGroupHasPeers(ctx, newNSGroup.AccountID, newNSGroup.Groups)
	if err != nil {
		return false, err
	}

	if hasPeers {
		return true, nil
	}

	return am.anyGroupHasPeers(ctx, oldNSGroup.AccountID, oldNSGroup.Groups)
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

func validateGroups(list []string, groups []*nbgroup.Group) error {
	if len(list) == 0 {
		return status.Errorf(status.InvalidArgument, "the list of group IDs should not be empty")
	}

	for _, id := range list {
		if id == "" {
			return status.Errorf(status.InvalidArgument, "group ID should not be empty string")
		}

		found := slices.ContainsFunc(groups, func(group *nbgroup.Group) bool { return group.ID == id })
		if !found {
			return status.Errorf(status.InvalidArgument, "group id %s not found", id)
		}
	}

	return nil
}

var domainMatcher = regexp.MustCompile(domainPattern)

func validateDomain(domain string) error {
	if !domainMatcher.MatchString(domain) {
		return errors.New("domain should consists of only letters, numbers, and hyphens with no leading, trailing hyphens, or spaces")
	}

	labels, valid := dns.IsDomainName(domain)
	if !valid {
		return errors.New("invalid domain name")
	}

	if labels < 2 {
		return errors.New("domain should consists of a minimum of two labels")
	}

	return nil
}
