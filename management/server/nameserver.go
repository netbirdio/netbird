package server

import (
	nbdns "github.com/netbirdio/netbird/dns"
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

	return nil, nil
}

// SaveNameServerGroup saves nameserver group
func (am *DefaultAccountManager) SaveNameServerGroup(accountID string, nsGroupToSave *nbdns.NameServerGroup) error {
	am.mux.Lock()
	defer am.mux.Unlock()
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
