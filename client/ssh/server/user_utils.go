package server

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	ErrPrivilegeRequired    = errors.New("SeAssignPrimaryTokenPrivilege required for user switching - NetBird must run with elevated privileges")
	ErrPrivilegedUserSwitch = errors.New("cannot switch to privileged user - current user lacks required privileges")
)

// isPlatformUnix returns true for Unix-like platforms (Linux, macOS, etc.)
func isPlatformUnix() bool {
	return getCurrentOS() != "windows"
}

// Dependency injection variables for testing - allows mocking dynamic runtime checks
var (
	getCurrentUser         = user.Current
	lookupUser             = user.Lookup
	getCurrentOS           = func() string { return runtime.GOOS }
	getIsProcessPrivileged = isCurrentProcessPrivileged

	getEuid = os.Geteuid
)

const (
	// FeatureSSHLogin represents SSH login operations for privilege checking
	FeatureSSHLogin = "SSH login"
	// FeatureSFTP represents SFTP operations for privilege checking
	FeatureSFTP = "SFTP"
)

// PrivilegeCheckRequest represents a privilege check request
type PrivilegeCheckRequest struct {
	// Username being requested (empty = current user)
	RequestedUsername         string
	FeatureSupportsUserSwitch bool // Does this feature/operation support user switching?
	FeatureName               string
}

// PrivilegeCheckResult represents the result of a privilege check
type PrivilegeCheckResult struct {
	// Allowed indicates whether the privilege check passed
	Allowed bool
	// User is the effective user to use for the operation (nil if not allowed)
	User *user.User
	// Error contains the reason for denial (nil if allowed)
	Error error
	// UsedFallback indicates we fell back to current user instead of requested user.
	// This happens on Unix when running as an unprivileged user (e.g., in containers)
	// where there's no point in user switching since we lack privileges anyway.
	// When true, all privilege checks have already been performed and no additional
	// privilege dropping or root checks are needed - the current user is the target.
	UsedFallback bool
	// RequiresUserSwitching indicates whether user switching will actually occur
	// (false for fallback cases where no actual switching happens)
	RequiresUserSwitching bool
}

// CheckPrivileges performs comprehensive privilege checking for all SSH features.
// This is the single source of truth for privilege decisions across the SSH server.
func (s *Server) CheckPrivileges(req PrivilegeCheckRequest) PrivilegeCheckResult {
	context, err := s.buildPrivilegeCheckContext(req.FeatureName)
	if err != nil {
		return PrivilegeCheckResult{Allowed: false, Error: err}
	}

	// Handle empty username case - but still check root access controls
	if req.RequestedUsername == "" {
		if isPrivilegedUsername(context.currentUser.Username) && !context.allowRoot {
			return PrivilegeCheckResult{
				Allowed: false,
				Error:   &PrivilegedUserError{Username: context.currentUser.Username},
			}
		}
		return PrivilegeCheckResult{
			Allowed:               true,
			User:                  context.currentUser,
			RequiresUserSwitching: false,
		}
	}

	return s.checkUserRequest(context, req)
}

// buildPrivilegeCheckContext gathers all the context needed for privilege checking
func (s *Server) buildPrivilegeCheckContext(featureName string) (*privilegeCheckContext, error) {
	currentUser, err := getCurrentUser()
	if err != nil {
		return nil, fmt.Errorf("get current user for %s: %w", featureName, err)
	}

	s.mu.RLock()
	allowRoot := s.allowRootLogin
	s.mu.RUnlock()

	return &privilegeCheckContext{
		currentUser:           currentUser,
		currentUserPrivileged: getIsProcessPrivileged(),
		allowRoot:             allowRoot,
	}, nil
}

// checkUserRequest handles normal privilege checking flow for specific usernames
func (s *Server) checkUserRequest(ctx *privilegeCheckContext, req PrivilegeCheckRequest) PrivilegeCheckResult {
	if !ctx.currentUserPrivileged && isPlatformUnix() {
		log.Debugf("Unix non-privileged shortcut: falling back to current user %s for %s (requested: %s)",
			ctx.currentUser.Username, req.FeatureName, req.RequestedUsername)
		return PrivilegeCheckResult{
			Allowed:               true,
			User:                  ctx.currentUser,
			UsedFallback:          true,
			RequiresUserSwitching: false,
		}
	}

	resolvedUser, err := s.resolveRequestedUser(req.RequestedUsername)
	if err != nil {
		// Calculate if user switching would be required even if lookup failed
		needsUserSwitching := !isSameUser(req.RequestedUsername, ctx.currentUser.Username)
		return PrivilegeCheckResult{
			Allowed:               false,
			Error:                 err,
			RequiresUserSwitching: needsUserSwitching,
		}
	}

	needsUserSwitching := !isSameResolvedUser(resolvedUser, ctx.currentUser)

	if isPrivilegedUsername(resolvedUser.Username) && !ctx.allowRoot {
		return PrivilegeCheckResult{
			Allowed:               false,
			Error:                 &PrivilegedUserError{Username: resolvedUser.Username},
			RequiresUserSwitching: needsUserSwitching,
		}
	}

	if needsUserSwitching && !req.FeatureSupportsUserSwitch {
		return PrivilegeCheckResult{
			Allowed:               false,
			Error:                 fmt.Errorf("%s: user switching not supported by this feature", req.FeatureName),
			RequiresUserSwitching: needsUserSwitching,
		}
	}

	return PrivilegeCheckResult{
		Allowed:               true,
		User:                  resolvedUser,
		RequiresUserSwitching: needsUserSwitching,
	}
}

// resolveRequestedUser resolves a username to its canonical user identity
func (s *Server) resolveRequestedUser(requestedUsername string) (*user.User, error) {
	if requestedUsername == "" {
		return getCurrentUser()
	}

	if err := validateUsername(requestedUsername); err != nil {
		return nil, fmt.Errorf("invalid username %q: %w", requestedUsername, err)
	}

	u, err := lookupUser(requestedUsername)
	if err != nil {
		return nil, &UserNotFoundError{Username: requestedUsername, Cause: err}
	}
	return u, nil
}

// isSameResolvedUser compares two resolved user identities
func isSameResolvedUser(user1, user2 *user.User) bool {
	if user1 == nil || user2 == nil {
		return user1 == user2
	}
	return user1.Uid == user2.Uid
}

// privilegeCheckContext holds all context needed for privilege checking
type privilegeCheckContext struct {
	currentUser           *user.User
	currentUserPrivileged bool
	allowRoot             bool
}

// isSameUser checks if two usernames refer to the same user
// SECURITY: This function must be conservative - it should only return true
// when we're certain both usernames refer to the exact same user identity
func isSameUser(requestedUsername, currentUsername string) bool {
	// Empty requested username means current user
	if requestedUsername == "" {
		return true
	}

	// Exact match (most common case)
	if getCurrentOS() == "windows" {
		if strings.EqualFold(requestedUsername, currentUsername) {
			return true
		}
	} else {
		if requestedUsername == currentUsername {
			return true
		}
	}

	// Windows domain resolution: only allow domain stripping when comparing
	// a bare username against the current user's domain-qualified name
	if getCurrentOS() == "windows" {
		return isWindowsSameUser(requestedUsername, currentUsername)
	}

	return false
}

// isWindowsSameUser handles Windows-specific user comparison with domain logic
func isWindowsSameUser(requestedUsername, currentUsername string) bool {
	// Extract domain and username parts
	extractParts := func(name string) (domain, user string) {
		// Handle DOMAIN\username format
		if idx := strings.LastIndex(name, `\`); idx != -1 {
			return name[:idx], name[idx+1:]
		}
		// Handle user@domain.com format
		if idx := strings.Index(name, "@"); idx != -1 {
			return name[idx+1:], name[:idx]
		}
		// No domain specified - local machine
		return "", name
	}

	reqDomain, reqUser := extractParts(requestedUsername)
	curDomain, curUser := extractParts(currentUsername)

	// Case-insensitive username comparison
	if !strings.EqualFold(reqUser, curUser) {
		return false
	}

	// If requested username has no domain, it refers to local machine user
	// Allow this to match the current user regardless of current user's domain
	if reqDomain == "" {
		return true
	}

	// If both have domains, they must match exactly (case-insensitive)
	return strings.EqualFold(reqDomain, curDomain)
}

// SetAllowRootLogin configures root login access
func (s *Server) SetAllowRootLogin(allow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowRootLogin = allow
}

// userNameLookup performs user lookup with root login permission check
func (s *Server) userNameLookup(username string) (*user.User, error) {
	result := s.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         username,
		FeatureSupportsUserSwitch: true,
		FeatureName:               FeatureSSHLogin,
	})

	if !result.Allowed {
		return nil, result.Error
	}

	return result.User, nil
}

// userPrivilegeCheck performs user lookup with full privilege check result
func (s *Server) userPrivilegeCheck(username string) (PrivilegeCheckResult, error) {
	result := s.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         username,
		FeatureSupportsUserSwitch: true,
		FeatureName:               FeatureSSHLogin,
	})

	if !result.Allowed {
		return result, result.Error
	}

	return result, nil
}

// isPrivilegedUsername checks if the given username represents a privileged user across platforms.
// On Unix: root
// On Windows: Administrator, SYSTEM (case-insensitive)
// Handles domain-qualified usernames like "DOMAIN\Administrator" or "user@domain.com"
func isPrivilegedUsername(username string) bool {
	if getCurrentOS() != "windows" {
		return username == "root"
	}

	bareUsername := username
	// Handle Windows domain format: DOMAIN\username
	if idx := strings.LastIndex(username, `\`); idx != -1 {
		bareUsername = username[idx+1:]
	}
	// Handle email-style format: username@domain.com
	if idx := strings.Index(bareUsername, "@"); idx != -1 {
		bareUsername = bareUsername[:idx]
	}

	return isWindowsPrivilegedUser(bareUsername)
}

// isWindowsPrivilegedUser checks if a bare username (domain already stripped) represents a Windows privileged account
func isWindowsPrivilegedUser(bareUsername string) bool {
	// common privileged usernames (case insensitive)
	privilegedNames := []string{
		"administrator",
		"admin",
		"root",
		"system",
		"localsystem",
		"networkservice",
		"localservice",
	}

	usernameLower := strings.ToLower(bareUsername)
	for _, privilegedName := range privilegedNames {
		if usernameLower == privilegedName {
			return true
		}
	}

	// computer accounts (ending with $) are not privileged by themselves
	// They only gain privileges through group membership or specific SIDs

	if targetUser, err := lookupUser(bareUsername); err == nil {
		return isWindowsPrivilegedSID(targetUser.Uid)
	}

	return false
}

// isWindowsPrivilegedSID checks if a Windows SID represents a privileged account
func isWindowsPrivilegedSID(sid string) bool {
	privilegedSIDs := []string{
		"S-1-5-18",     // Local System (SYSTEM)
		"S-1-5-19",     // Local Service (NT AUTHORITY\LOCAL SERVICE)
		"S-1-5-20",     // Network Service (NT AUTHORITY\NETWORK SERVICE)
		"S-1-5-32-544", // Administrators group (BUILTIN\Administrators)
		"S-1-5-500",    // Built-in Administrator account (local machine RID 500)
	}

	for _, privilegedSID := range privilegedSIDs {
		if sid == privilegedSID {
			return true
		}
	}

	// Check for domain administrator accounts (RID 500 in any domain)
	// Format: S-1-5-21-domain-domain-domain-500
	// This is reliable as RID 500 is reserved for the domain Administrator account
	if strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, "-500") {
		return true
	}

	// Check for other well-known privileged RIDs in domain contexts
	// RID 512 = Domain Admins group, RID 516 = Domain Controllers group
	if strings.HasPrefix(sid, "S-1-5-21-") {
		if strings.HasSuffix(sid, "-512") || // Domain Admins group
			strings.HasSuffix(sid, "-516") || // Domain Controllers group
			strings.HasSuffix(sid, "-519") { // Enterprise Admins group
			return true
		}
	}

	return false
}

// isCurrentProcessPrivileged checks if the current process is running with elevated privileges.
// On Unix systems, this means running as root (UID 0).
// On Windows, this means running as Administrator or SYSTEM.
func isCurrentProcessPrivileged() bool {
	if getCurrentOS() == "windows" {
		return isWindowsElevated()
	}
	return getEuid() == 0
}

// isWindowsElevated checks if the current process is running with elevated privileges on Windows
func isWindowsElevated() bool {
	currentUser, err := getCurrentUser()
	if err != nil {
		log.Errorf("failed to get current user for privilege check, assuming non-privileged: %v", err)
		return false
	}

	if isWindowsPrivilegedSID(currentUser.Uid) {
		log.Debugf("Windows user switching supported: running as privileged SID %s", currentUser.Uid)
		return true
	}

	if isPrivilegedUsername(currentUser.Username) {
		log.Debugf("Windows user switching supported: running as privileged username %s", currentUser.Username)
		return true
	}

	log.Debugf("Windows user switching not supported: not running as privileged user (current: %s)", currentUser.Uid)
	return false
}
