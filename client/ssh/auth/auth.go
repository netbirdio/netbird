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

// Authorize validates if a user is authorized to login as the specified OS user.
// Returns a success message describing how authorization was granted, or an error.
func (a *Authorizer) Authorize(jwtUserID, osUsername string) (string, error) {
	if jwtUserID == "" {
		return "", fmt.Errorf("JWT user ID is empty for OS user %q: %w", osUsername, ErrEmptyUserID)
	}

	// Hash the JWT user ID for comparison
	hashedUserID, err := sshuserhash.HashUserID(jwtUserID)
	if err != nil {
		return "", fmt.Errorf("hash user ID %q for OS user %q: %w", jwtUserID, osUsername, err)
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// Find the index of this user in the authorized list
	userIndex, found := a.findUserIndex(hashedUserID)
	if !found {
		return "", fmt.Errorf("user %q (hash: %s) not in authorized list for OS user %q: %w", jwtUserID, hashedUserID, osUsername, ErrUserNotAuthorized)
	}

	return a.checkMachineUserMapping(jwtUserID, osUsername, userIndex)
}

// checkMachineUserMapping validates if a user's index is authorized for the specified OS user
// Checks wildcard mapping first, then specific OS user mappings
func (a *Authorizer) checkMachineUserMapping(jwtUserID, osUsername string, userIndex int) (string, error) {
	// If wildcard exists and user's index is in the wildcard list, allow access to any OS user
	if wildcardIndexes, hasWildcard := a.machineUsers[Wildcard]; hasWildcard {
		if a.isIndexInList(uint32(userIndex), wildcardIndexes) {
			return fmt.Sprintf("granted via wildcard (index: %d)", userIndex), nil
		}
	}

	// Check for specific OS username mapping
	allowedIndexes, hasMachineUserMapping := a.machineUsers[osUsername]
	if !hasMachineUserMapping {
		// No mapping for this OS user - deny by default (fail closed)
		return "", fmt.Errorf("no machine user mapping for OS user %q (JWT user: %s): %w", osUsername, jwtUserID, ErrNoMachineUserMapping)
	}

	// Check if user's index is in the allowed indexes for this specific OS user
	if !a.isIndexInList(uint32(userIndex), allowedIndexes) {
		return "", fmt.Errorf("user %q not mapped to OS user %q (index: %d): %w", jwtUserID, osUsername, userIndex, ErrUserNotMappedToOSUser)
	}

	return fmt.Sprintf("granted (index: %d)", userIndex), nil
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
