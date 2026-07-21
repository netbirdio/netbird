package sessionauth

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
	// sessionPubKeyLen is the size of an X25519 static public key in bytes.
	sessionPubKeyLen = 32
)

var (
	ErrEmptyUserID           = errors.New("JWT user ID is empty")
	ErrUserNotAuthorized     = errors.New("user is not authorized to access this peer")
	ErrNoMachineUserMapping  = errors.New("no authorization mapping for OS user")
	ErrUserNotMappedToOSUser = errors.New("user is not authorized to login as OS user")
	ErrSessionKeyNotKnown    = errors.New("session pubkey not registered")
)

// Authorizer handles SSH fine-grained access control authorization
type Authorizer struct {
	// UserIDClaim is the JWT claim to extract the user ID from
	userIDClaim string

	// authorizedUsers is a list of hashed user IDs authorized to access this peer
	authorizedUsers []sshuserhash.UserIDHash

	// machineUsers maps OS login usernames to lists of authorized user indexes
	machineUsers map[string][]uint32

	// sessionPubKeys maps an X25519 static public key (as map-safe
	// array) to the hashed user identity that key authenticates as.
	// Populated from management's temporary-access flow; used by VNC to
	// authenticate via the Noise_IK handshake.
	sessionPubKeys map[[sessionPubKeyLen]byte]sshuserhash.UserIDHash
	// sessionDisplayNames mirrors sessionPubKeys with the optional
	// human-readable display name management associated with each
	// session key. Used by the per-connection UI approval prompt; not
	// consulted by any authorization decision.
	sessionDisplayNames map[[sessionPubKeyLen]byte]string

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

	// SessionPubKeys binds ephemeral X25519 static public keys to hashed
	// user identities. Populated for VNC; ignored on the SSH side.
	SessionPubKeys []SessionPubKey
}

// SessionPubKey is a single ephemeral-key entry: the 32-byte X25519
// static public key plus the hashed user identity it authenticates as,
// optionally plus a human-readable display name for the UI approval
// prompt to identify the requester.
type SessionPubKey struct {
	PubKey      []byte
	UserIDHash  sshuserhash.UserIDHash
	DisplayName string
}

// NewAuthorizer creates a new SSH authorizer with empty configuration
func NewAuthorizer() *Authorizer {
	a := &Authorizer{
		userIDClaim:         DefaultUserIDClaim,
		machineUsers:        make(map[string][]uint32),
		sessionPubKeys:      make(map[[sessionPubKeyLen]byte]sshuserhash.UserIDHash),
		sessionDisplayNames: make(map[[sessionPubKeyLen]byte]string),
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
		a.sessionPubKeys = make(map[[sessionPubKeyLen]byte]sshuserhash.UserIDHash)
		a.sessionDisplayNames = make(map[[sessionPubKeyLen]byte]string)
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

	sessionPubKeys := make(map[[sessionPubKeyLen]byte]sshuserhash.UserIDHash, len(config.SessionPubKeys))
	sessionDisplayNames := make(map[[sessionPubKeyLen]byte]string, len(config.SessionPubKeys))
	conflicted := make(map[[sessionPubKeyLen]byte]struct{})
	for _, e := range config.SessionPubKeys {
		if len(e.PubKey) != sessionPubKeyLen {
			continue
		}
		var key [sessionPubKeyLen]byte
		copy(key[:], e.PubKey)
		if _, bad := conflicted[key]; bad {
			continue
		}
		if existing, ok := sessionPubKeys[key]; ok && existing != e.UserIDHash {
			log.Warnf("SSH auth: session pubkey bound to conflicting user hashes; dropping binding")
			delete(sessionPubKeys, key)
			delete(sessionDisplayNames, key)
			conflicted[key] = struct{}{}
			continue
		}
		sessionPubKeys[key] = e.UserIDHash
		if e.DisplayName != "" {
			sessionDisplayNames[key] = e.DisplayName
		}
	}
	a.sessionPubKeys = sessionPubKeys
	a.sessionDisplayNames = sessionDisplayNames

	log.Debugf("SSH auth: updated with %d authorized users, %d machine user mappings, %d session pubkeys",
		len(config.AuthorizedUsers), len(machineUsers), len(sessionPubKeys))
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

// LookupSessionKey resolves a Noise-verified static public key to the
// hashed user identity registered with it. Fails closed when the key is
// unknown.
func (a *Authorizer) LookupSessionKey(pubKey []byte) (sshuserhash.UserIDHash, error) {
	var zero sshuserhash.UserIDHash
	if len(pubKey) != sessionPubKeyLen {
		return zero, fmt.Errorf("session pubkey wrong length: %d", len(pubKey))
	}
	var key [sessionPubKeyLen]byte
	copy(key[:], pubKey)
	a.mu.RLock()
	hash, ok := a.sessionPubKeys[key]
	a.mu.RUnlock()
	if !ok {
		return zero, ErrSessionKeyNotKnown
	}
	return hash, nil
}

// LookupSessionDisplayName returns the human-readable display name
// management associated with a session pubkey, or empty string when none
// is recorded. Never returns an error: a missing/unknown key reports as
// "" and the caller falls back to other identifiers.
func (a *Authorizer) LookupSessionDisplayName(pubKey []byte) string {
	if len(pubKey) != sessionPubKeyLen {
		return ""
	}
	var key [sessionPubKeyLen]byte
	copy(key[:], pubKey)
	a.mu.RLock()
	name := a.sessionDisplayNames[key]
	a.mu.RUnlock()
	return name
}

// AuthorizeOSUserBySessionKey resolves the OS-user mapping for a session
// key. Mirrors Authorize but skips the JWT-hash step since the key has
// already been verified and the user identity hash is in hand.
func (a *Authorizer) AuthorizeOSUserBySessionKey(userIDHash sshuserhash.UserIDHash, osUsername string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	userIndex, found := a.findUserIndex(userIDHash)
	if !found {
		return "", fmt.Errorf("session user (hash: %s) not in authorized list for OS user %q: %w", userIDHash, osUsername, ErrUserNotAuthorized)
	}
	return a.checkMachineUserMapping("session", osUsername, userIndex)
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
