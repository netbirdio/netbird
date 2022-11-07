package server

import (
	"github.com/miekg/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/rs/xid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strconv"
	"unicode/utf8"
)

const (
	// UpdateNameServerGroupName indicates a nameserver group name update operation
	UpdateNameServerGroupName NameServerGroupUpdateOperationType = iota
	// UpdateNameServerGroupDescription indicates a nameserver group description update operation
	UpdateNameServerGroupDescription
	// UpdateNameServerGroupNameServers indicates a nameserver group nameservers list update operation
	UpdateNameServerGroupNameServers
	// UpdateNameServerGroupGroups indicates a nameserver group' groups update operation
	UpdateNameServerGroupGroups
	// UpdateNameServerGroupEnabled indicates a nameserver group status update operation
	UpdateNameServerGroupEnabled
	// UpdateNameServerGroupPrimary indicates a nameserver group primary status update operation
	UpdateNameServerGroupPrimary
	// UpdateNameServerGroupDomains indicates a nameserver group' domains update operation
	UpdateNameServerGroupDomains
)

// NameServerGroupUpdateOperationType operation type
type NameServerGroupUpdateOperationType int

func (t NameServerGroupUpdateOperationType) String() string {
	switch t {
	case UpdateNameServerGroupDescription:
		return "UpdateNameServerGroupDescription"
	case UpdateNameServerGroupName:
		return "UpdateNameServerGroupName"
	case UpdateNameServerGroupNameServers:
		return "UpdateNameServerGroupNameServers"
	case UpdateNameServerGroupGroups:
		return "UpdateNameServerGroupGroups"
	case UpdateNameServerGroupEnabled:
		return "UpdateNameServerGroupEnabled"
	case UpdateNameServerGroupPrimary:
		return "UpdateNameServerGroupPrimary"
	case UpdateNameServerGroupDomains:
		return "UpdateNameServerGroupDomains"
	default:
		return "InvalidOperation"
	}
}

// NameServerGroupUpdateOperation operation object with type and values to be applied
type NameServerGroupUpdateOperation struct {
	Type   NameServerGroupUpdateOperationType
	Values []string
}

// GetNameServerGroup gets a nameserver group object from account and nameserver group IDs
func (am *DefaultAccountManager) GetNameServerGroup(accountID, nsGroupID string) (*nbdns.NameServerGroup, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	nsGroup, found := account.NameServerGroups[nsGroupID]
	if found {
		return nsGroup.Copy(), nil
	}

	return nil, status.Errorf(codes.NotFound, "nameserver group with ID %s not found", nsGroupID)
}

// CreateNameServerGroup creates and saves a new nameserver group
func (am *DefaultAccountManager) CreateNameServerGroup(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool) (*nbdns.NameServerGroup, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	newNSGroup := &nbdns.NameServerGroup{
		ID:          xid.New().String(),
		Name:        name,
		Description: description,
		NameServers: nameServerList,
		Groups:      groups,
		Enabled:     enabled,
		Primary:     primary,
		Domains:     domains,
	}

	err = validateNameServerGroup(false, newNSGroup, account)
	if err != nil {
		return nil, err
	}

	if account.NameServerGroups == nil {
		account.NameServerGroups = make(map[string]*nbdns.NameServerGroup)
	}

	account.NameServerGroups[newNSGroup.ID] = newNSGroup

	account.Network.IncSerial()
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	return newNSGroup.Copy(), nil
}

// SaveNameServerGroup saves nameserver group
func (am *DefaultAccountManager) SaveNameServerGroup(accountID string, nsGroupToSave *nbdns.NameServerGroup) error {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	if nsGroupToSave == nil {
		return status.Errorf(codes.InvalidArgument, "nameserver group provided is nil")
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return status.Errorf(codes.NotFound, "account not found")
	}

	err = validateNameServerGroup(true, nsGroupToSave, account)
	if err != nil {
		return err
	}

	account.NameServerGroups[nsGroupToSave.ID] = nsGroupToSave

	account.Network.IncSerial()
	err = am.Store.SaveAccount(account)
	if err != nil {
		return err
	}

	return nil
}

// UpdateNameServerGroup updates existing nameserver group with set of operations
func (am *DefaultAccountManager) UpdateNameServerGroup(accountID, nsGroupID string, operations []NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	if len(operations) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "operations shouldn't be empty")
	}

	nsGroupToUpdate, ok := account.NameServerGroups[nsGroupID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "nameserver group ID %s no longer exists", nsGroupID)
	}

	newNSGroup := nsGroupToUpdate.Copy()

	for _, operation := range operations {
		valuesCount := len(operation.Values)
		if valuesCount < 1 {
			return nil, status.Errorf(codes.InvalidArgument, "operation %s contains invalid number of values, it should be at least 1", operation.Type.String())
		}

		for _, value := range operation.Values {
			if value == "" {
				return nil, status.Errorf(codes.InvalidArgument, "operation %s contains invalid empty string value", operation.Type.String())
			}
		}
		switch operation.Type {
		case UpdateNameServerGroupDescription:
			newNSGroup.Description = operation.Values[0]
		case UpdateNameServerGroupName:
			if valuesCount > 1 {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse name values, expected 1 value got %d", valuesCount)
			}
			err = validateNSGroupName(operation.Values[0], nsGroupID, account.NameServerGroups)
			if err != nil {
				return nil, err
			}
			newNSGroup.Name = operation.Values[0]
		case UpdateNameServerGroupNameServers:
			var nsList []nbdns.NameServer
			for _, url := range operation.Values {
				ns, err := nbdns.ParseNameServerURL(url)
				if err != nil {
					return nil, err
				}
				nsList = append(nsList, ns)
			}
			err = validateNSList(nsList)
			if err != nil {
				return nil, err
			}
			newNSGroup.NameServers = nsList
		case UpdateNameServerGroupGroups:
			err = validateGroups(operation.Values, account.Groups)
			if err != nil {
				return nil, err
			}
			newNSGroup.Groups = operation.Values
		case UpdateNameServerGroupEnabled:
			enabled, err := strconv.ParseBool(operation.Values[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse enabled %s, not boolean", operation.Values[0])
			}
			newNSGroup.Enabled = enabled
		case UpdateNameServerGroupPrimary:
			primary, err := strconv.ParseBool(operation.Values[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse primary status %s, not boolean", operation.Values[0])
			}
			newNSGroup.Primary = primary
		case UpdateNameServerGroupDomains:
			err = validateDomainInput(false, operation.Values)
			if err != nil {
				return nil, err
			}
			newNSGroup.Domains = operation.Values
		}
	}

	account.NameServerGroups[nsGroupID] = newNSGroup

	account.Network.IncSerial()
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	return newNSGroup.Copy(), nil
}

// DeleteNameServerGroup deletes nameserver group with nsGroupID
func (am *DefaultAccountManager) DeleteNameServerGroup(accountID, nsGroupID string) error {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return status.Errorf(codes.NotFound, "account not found")
	}

	delete(account.NameServerGroups, nsGroupID)

	account.Network.IncSerial()
	err = am.Store.SaveAccount(account)
	if err != nil {
		return err
	}

	return nil
}

// ListNameServerGroups returns a list of nameserver groups from account
func (am *DefaultAccountManager) ListNameServerGroups(accountID string) ([]*nbdns.NameServerGroup, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	nsGroups := make([]*nbdns.NameServerGroup, 0, len(account.NameServerGroups))
	for _, item := range account.NameServerGroups {
		nsGroups = append(nsGroups, item.Copy())
	}

	return nsGroups, nil
}

func validateNameServerGroup(existingGroup bool, nameserverGroup *nbdns.NameServerGroup, account *Account) error {
	nsGroupID := ""
	if existingGroup {
		nsGroupID = nameserverGroup.ID
		_, found := account.NameServerGroups[nsGroupID]
		if !found {
			return status.Errorf(codes.NotFound, "nameserver group with ID %s was not found", nsGroupID)
		}
	}

	err := validateDomainInput(nameserverGroup.Primary, nameserverGroup.Domains)
	if err != nil {
		return err
	}

	err = validateNSGroupName(nameserverGroup.Name, nsGroupID, account.NameServerGroups)
	if err != nil {
		return err
	}

	err = validateNSList(nameserverGroup.NameServers)
	if err != nil {
		return err
	}

	err = validateGroups(nameserverGroup.Groups, account.Groups)
	if err != nil {
		return err
	}

	return nil
}

func validateDomainInput(primary bool, domains []string) error {
	if !primary && len(domains) == 0 {
		return status.Errorf(codes.InvalidArgument, "nameserver group primary status is false and domains are empty,"+
			" it should be primary or have at least one domain")
	}
	if primary && len(domains) != 0 {
		return status.Errorf(codes.InvalidArgument, "nameserver group primary status is true and domains are not empty,"+
			" you should set either primary or domain")
	}
	for _, domain := range domains {
		_, valid := dns.IsDomainName(domain)
		if !valid {
			return status.Errorf(codes.InvalidArgument, "nameserver group got an invalid domain: %s", domain)
		}
	}
	return nil
}

func validateNSGroupName(name, nsGroupID string, nsGroupMap map[string]*nbdns.NameServerGroup) error {
	if utf8.RuneCountInString(name) > nbdns.MaxGroupNameChar || name == "" {
		return status.Errorf(codes.InvalidArgument, "nameserver group name should be between 1 and %d", nbdns.MaxGroupNameChar)
	}

	for _, nsGroup := range nsGroupMap {
		if name == nsGroup.Name && nsGroup.ID != nsGroupID {
			return status.Errorf(codes.InvalidArgument, "a nameserver group with name %s already exist", name)
		}
	}

	return nil
}

func validateNSList(list []nbdns.NameServer) error {
	nsListLenght := len(list)
	if nsListLenght == 0 || nsListLenght > 2 {
		return status.Errorf(codes.InvalidArgument, "the list of nameservers should be 1 or 2, got %d", len(list))
	}
	return nil
}

func validateGroups(list []string, groups map[string]*Group) error {
	if len(list) == 0 {
		return status.Errorf(codes.InvalidArgument, "the list of group IDs should not be empty")
	}

	for _, id := range list {
		if id == "" {
			return status.Errorf(codes.InvalidArgument, "group ID should not be empty string")
		}
		found := false
		for groupID := range groups {
			if id == groupID {
				found = true
				break
			}
		}
		if !found {
			return status.Errorf(codes.InvalidArgument, "group id %s not found", id)
		}
	}

	return nil
}
