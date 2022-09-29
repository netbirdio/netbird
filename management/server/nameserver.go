package server

import (
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/rs/xid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	am.mux.Lock()
	defer am.mux.Unlock()

	return nil, nil
}

// CreateNameServerGroup creates and saves a new nameserver group
func (am *DefaultAccountManager) CreateNameServerGroup(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, enabled bool) (*nbdns.NameServerGroup, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

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
	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	return newNSGroup, nil
}

// SaveNameServerGroup saves nameserver group
func (am *DefaultAccountManager) SaveNameServerGroup(accountID string, nsGroupToSave *nbdns.NameServerGroup) error {
	am.mux.Lock()
	defer am.mux.Unlock()

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
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	return nil
}

// UpdateNameServerGroup updates existing nameserver group with set of operations
func (am *DefaultAccountManager) UpdateNameServerGroup(accountID, nsGroupID string, operations []NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	return nil, nil
}

// DeleteNameServerGroup deletes nameserver group with nsGroupID
func (am *DefaultAccountManager) DeleteNameServerGroup(accountID, nsGroupID string) error {
	am.mux.Lock()
	defer am.mux.Unlock()

	return nil
}

// ListNameServerGroups returns a list of nameserver groups from account
func (am *DefaultAccountManager) ListNameServerGroups(accountID string) ([]*nbdns.NameServerGroup, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	return nil, nil
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

	err := validateNSGroupName(nameserverGroup.Name, nsGroupID, account.NameServerGroups)
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
