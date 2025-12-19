package auth

import (
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	sshuserhash "github.com/netbirdio/netbird/shared/sshauth"
)

const (
	// DefaultUserIDClaim is the default JWT claim used to extract user IDs
	DefaultUserIDClaim = "sub"
	// Wildcard is a special user ID that matches all users
	Wildcard = "*"
)

var (
	ErrEmptyUserID           = errors.New("JWT user ID is empty")
	ErrUserNotAuthorized     = errors.New("user is not authorized to access this peer")
	ErrNoMachineUserMapping  = errors.New("no authorization mapping for OS user")
	ErrUserNotMappedToOSUser = errors.New("user is not authorized to login as OS user")
)

// Authorizer handles SSH fine-grained access control authorization
type Authorizer struct {
	// UserIDClaim is the JWT claim to extract the user ID from
	userIDClaim string

	// authorizedUsers is a list of hashed user IDs authorized to access this peer
	authorizedUsers []sshuserhash.UserIDHash

	// machineUsers maps OS login usernames to lists of authorized user indexes
	machineUsers map[string][]uint32

	// mu protects the list of users
	mu sync.RWMutex
}

// Config contains configuration for the SSH authorizer
type Config struct {
	// UserIDClaim is the JWT claim to extract the user ID from (e.g., "sub", "email")
	UserIDClaim string

	// AuthorizedUsers is a list of hashed user IDs (FNV-1a 64-bit) authorized to access this peer
	AuthorizedUsers []sshuserhash.UserIDHash

	// MachineUsers maps OS login usernames to indexes in AuthorizedUsers
	// If a user wants to login as a specific OS user, their index must be in the corresponding list
	MachineUsers map[string][]uint32
}

// NewAuthorizer creates a new SSH authorizer with empty configuration
func NewAuthorizer() *Authorizer {
	a := &Authorizer{
		userIDClaim:  DefaultUserIDClaim,
		machineUsers: make(map[string][]uint32),
	}

	return a
}

// Update updates the authorizer configuration with new values
func (a *Authorizer) Update(config *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if config == nil {
		// Clear authorization
		a.userIDClaim = DefaultUserIDClaim
		a.authorizedUsers = []sshuserhash.UserIDHash{}
		a.machineUsers = make(map[string][]uint32)
		log.Info("SSH authorization cleared")
		return
	}

	userIDClaim := config.UserIDClaim
	if userIDClaim == "" {
		userIDClaim = DefaultUserIDClaim
	}
	a.userIDClaim = userIDClaim

	// Store authorized users list
	a.authorizedUsers = config.AuthorizedUsers

	// Store machine users mapping
	machineUsers := make(map[string][]uint32)
	for osUser, indexes := range config.MachineUsers {
		if len(indexes) > 0 {
			machineUsers[osUser] = indexes
		}
	}
	a.machineUsers = machineUsers

	log.Debugf("SSH auth: updated with %d authorized users, %d machine user mappings",
		len(config.AuthorizedUsers), len(machineUsers))
}

// Authorize validates if a user is authorized to login as the specified OS user
// Returns nil if authorized, or an error describing why authorization failed
func (a *Authorizer) Authorize(jwtUserID, osUsername string) error {
	if jwtUserID == "" {
		log.Warnf("SSH auth denied: JWT user ID is empty for OS user '%s'", osUsername)
		return ErrEmptyUserID
	}

	// Hash the JWT user ID for comparison
	hashedUserID, err := sshuserhash.HashUserID(jwtUserID)
	if err != nil {
		log.Errorf("SSH auth denied: failed to hash user ID '%s' for OS user '%s': %v", jwtUserID, osUsername, err)
		return fmt.Errorf("failed to hash user ID: %w", err)
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// Find the index of this user in the authorized list
	userIndex, found := a.findUserIndex(hashedUserID)
	if !found {
		log.Warnf("SSH auth denied: user '%s' (hash: %s) not in authorized list for OS user '%s'", jwtUserID, hashedUserID, osUsername)
		return ErrUserNotAuthorized
	}

	// Check machine user mapping
	allowedIndexes, hasMachineUserMapping := a.machineUsers[osUsername]
	if !hasMachineUserMapping {
		// No mapping for this OS user - deny by default (fail closed)
		log.Warnf("SSH auth denied: no machine user mapping for OS user '%s' (JWT user: %s)", osUsername, jwtUserID)
		return ErrNoMachineUserMapping
	}

	// Check if user's index is in the allowed indexes for this OS user
	if !a.isIndexInList(uint32(userIndex), allowedIndexes) {
		log.Warnf("SSH auth denied: user '%s' not mapped to OS user '%s' (user index: %d)", jwtUserID, osUsername, userIndex)
		return ErrUserNotMappedToOSUser
	}

	log.Infof("SSH auth granted: user '%s' authorized for OS user '%s' (index: %d)", jwtUserID, osUsername, userIndex)
	return nil
}

// GetUserIDClaim returns the JWT claim name used to extract user IDs
func (a *Authorizer) GetUserIDClaim() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.userIDClaim
}

// findUserIndex finds the index of a hashed user ID in the authorized users list
// Returns the index and true if found, 0 and false if not found
func (a *Authorizer) findUserIndex(hashedUserID sshuserhash.UserIDHash) (int, bool) {
	for i, id := range a.authorizedUsers {
		if id == hashedUserID {
			return i, true
		}
	}
	return 0, false
}

// isIndexInList checks if an index exists in a list of indexes
func (a *Authorizer) isIndexInList(index uint32, indexes []uint32) bool {
	for _, idx := range indexes {
		if idx == index {
			return true
		}
	}
	return false
}
