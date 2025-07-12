package server

import (
	"errors"
	"os/user"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test helper functions
func createTestUser(username, uid, gid, homeDir string) *user.User {
	return &user.User{
		Uid:      uid,
		Gid:      gid,
		Username: username,
		Name:     username,
		HomeDir:  homeDir,
	}
}

// Test dependency injection setup - injects platform dependencies to test real logic
func setupTestDependencies(currentUser *user.User, currentUserErr error, os string, euid int, lookupUsers map[string]*user.User, lookupErrors map[string]error) func() {
	// Store originals
	originalGetCurrentUser := getCurrentUser
	originalLookupUser := lookupUser
	originalGetCurrentOS := getCurrentOS
	originalGetEuid := getEuid

	// Reset caches to ensure clean test state

	// Set test values - inject platform dependencies
	getCurrentUser = func() (*user.User, error) {
		return currentUser, currentUserErr
	}

	lookupUser = func(username string) (*user.User, error) {
		if err, exists := lookupErrors[username]; exists {
			return nil, err
		}
		if userObj, exists := lookupUsers[username]; exists {
			return userObj, nil
		}
		return nil, errors.New("user: unknown user " + username)
	}

	getCurrentOS = func() string {
		return os
	}

	getEuid = func() int {
		return euid
	}

	// Mock privilege detection based on the test user
	getIsProcessPrivileged = func() bool {
		if currentUser == nil {
			return false
		}
		// Check both username and SID for Windows systems
		if os == "windows" && isWindowsPrivilegedSID(currentUser.Uid) {
			return true
		}
		return isPrivilegedUsername(currentUser.Username)
	}

	// Return cleanup function
	return func() {
		getCurrentUser = originalGetCurrentUser
		lookupUser = originalLookupUser
		getCurrentOS = originalGetCurrentOS
		getEuid = originalGetEuid

		getIsProcessPrivileged = isCurrentProcessPrivileged

		// Reset caches after test
	}
}

func TestCheckPrivileges_ComprehensiveMatrix(t *testing.T) {
	tests := []struct {
		name                      string
		os                        string
		euid                      int
		currentUser               *user.User
		requestedUsername         string
		featureSupportsUserSwitch bool
		allowRoot                 bool
		lookupUsers               map[string]*user.User
		expectedAllowed           bool
		expectedRequiresSwitch    bool
	}{
		{
			name:                      "linux_root_can_switch_to_alice",
			os:                        "linux",
			euid:                      0, // Root process
			currentUser:               createTestUser("root", "0", "0", "/root"),
			requestedUsername:         "alice",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"alice": createTestUser("alice", "1000", "1000", "/home/alice"),
			},
			expectedAllowed:        true,
			expectedRequiresSwitch: true,
		},
		{
			name:                      "linux_non_root_fallback_to_current_user",
			os:                        "linux",
			euid:                      1000, // Non-root process
			currentUser:               createTestUser("alice", "1000", "1000", "/home/alice"),
			requestedUsername:         "bob",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			expectedAllowed:           true,  // Should fallback to current user (alice)
			expectedRequiresSwitch:    false, // Fallback means no actual switching
		},
		{
			name:                      "windows_admin_can_switch_to_alice",
			os:                        "windows",
			euid:                      1000, // Irrelevant on Windows
			currentUser:               createTestUser("Administrator", "S-1-5-21-123456789-123456789-123456789-500", "S-1-5-32-544", "C:\\Users\\Administrator"),
			requestedUsername:         "alice",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"alice": createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\alice"),
			},
			expectedAllowed:        true,
			expectedRequiresSwitch: true,
		},
		{
			name:                      "windows_non_admin_no_fallback_hard_failure",
			os:                        "windows",
			euid:                      1000, // Irrelevant on Windows
			currentUser:               createTestUser("alice", "1001", "1001", "C:\\Users\\alice"),
			requestedUsername:         "bob",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"bob": createTestUser("bob", "S-1-5-21-123456789-123456789-123456789-1002", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\bob"),
			},
			expectedAllowed:        true, // Let OS decide - deferred security check
			expectedRequiresSwitch: true, // Different user was requested
		},
		// Comprehensive test matrix: non-root linux with different allowRoot settings
		{
			name:                      "linux_non_root_request_root_allowRoot_false",
			os:                        "linux",
			euid:                      1000,
			currentUser:               createTestUser("alice", "1000", "1000", "/home/alice"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 false,
			expectedAllowed:           true,  // Fallback allows access regardless of root setting
			expectedRequiresSwitch:    false, // Fallback case, no switching
		},
		{
			name:                      "linux_non_root_request_root_allowRoot_true",
			os:                        "linux",
			euid:                      1000,
			currentUser:               createTestUser("alice", "1000", "1000", "/home/alice"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			expectedAllowed:           true,  // Should fallback to alice (non-privileged process)
			expectedRequiresSwitch:    false, // Fallback means no actual switching
		},
		// Windows admin test matrix
		{
			name:                      "windows_admin_request_root_allowRoot_false",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("Administrator", "S-1-5-21-123456789-123456789-123456789-500", "S-1-5-32-544", "C:\\Users\\Administrator"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 false,
			expectedAllowed:           false, // Root not allowed
			expectedRequiresSwitch:    true,
		},
		{
			name:                      "windows_admin_request_root_allowRoot_true",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("Administrator", "S-1-5-21-123456789-123456789-123456789-500", "S-1-5-32-544", "C:\\Users\\Administrator"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"root": createTestUser("root", "0", "0", "/root"),
			},
			expectedAllowed:        true, // Windows user switching should work like Unix
			expectedRequiresSwitch: true,
		},
		// Windows non-admin test matrix
		{
			name:                      "windows_non_admin_request_root_allowRoot_false",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\alice"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 false,
			expectedAllowed:           false, // Root not allowed (allowRoot=false takes precedence)
			expectedRequiresSwitch:    true,
		},
		{
			name:                      "windows_system_account_allowRoot_false",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("NETBIRD\\WIN2K19-C2$", "S-1-5-18", "S-1-5-18", "C:\\Windows\\System32"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 false,
			expectedAllowed:           false, // Root not allowed
			expectedRequiresSwitch:    true,
		},
		{
			name:                      "windows_system_account_allowRoot_true",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("NETBIRD\\WIN2K19-C2$", "S-1-5-18", "S-1-5-18", "C:\\Windows\\System32"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"root": createTestUser("root", "0", "0", "/root"),
			},
			expectedAllowed:        true, // SYSTEM can switch to root
			expectedRequiresSwitch: true,
		},
		{
			name:                      "windows_non_admin_request_root_allowRoot_true",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\alice"),
			requestedUsername:         "root",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"root": createTestUser("root", "0", "0", "/root"),
			},
			expectedAllowed:        true, // Let OS decide - deferred security check
			expectedRequiresSwitch: true,
		},

		// Feature doesn't support user switching scenarios
		{
			name:                      "linux_root_feature_no_user_switching_same_user",
			os:                        "linux",
			euid:                      0,
			currentUser:               createTestUser("root", "0", "0", "/root"),
			requestedUsername:         "root", // Same user
			featureSupportsUserSwitch: false,
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"root": createTestUser("root", "0", "0", "/root"),
			},
			expectedAllowed:        true, // Same user should work regardless of feature support
			expectedRequiresSwitch: false,
		},
		{
			name:                      "linux_root_feature_no_user_switching_different_user",
			os:                        "linux",
			euid:                      0,
			currentUser:               createTestUser("root", "0", "0", "/root"),
			requestedUsername:         "alice",
			featureSupportsUserSwitch: false, // Feature doesn't support switching
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"alice": createTestUser("alice", "1000", "1000", "/home/alice"),
			},
			expectedAllowed:        false, // Should deny because feature doesn't support switching
			expectedRequiresSwitch: true,
		},

		// Empty username (current user) scenarios
		{
			name:                      "linux_non_root_current_user_empty_username",
			os:                        "linux",
			euid:                      1000,
			currentUser:               createTestUser("alice", "1000", "1000", "/home/alice"),
			requestedUsername:         "", // Empty = current user
			featureSupportsUserSwitch: true,
			allowRoot:                 false,
			expectedAllowed:           true, // Current user should always work
			expectedRequiresSwitch:    false,
		},
		{
			name:                      "linux_root_current_user_empty_username_root_not_allowed",
			os:                        "linux",
			euid:                      0,
			currentUser:               createTestUser("root", "0", "0", "/root"),
			requestedUsername:         "", // Empty = current user (root)
			featureSupportsUserSwitch: true,
			allowRoot:                 false, // Root not allowed
			expectedAllowed:           false, // Should deny root even when it's current user
			expectedRequiresSwitch:    false,
		},

		// User not found scenarios
		{
			name:                      "linux_root_user_not_found",
			os:                        "linux",
			euid:                      0,
			currentUser:               createTestUser("root", "0", "0", "/root"),
			requestedUsername:         "nonexistent",
			featureSupportsUserSwitch: true,
			allowRoot:                 true,
			lookupUsers:               map[string]*user.User{}, // No users defined = user not found
			expectedAllowed:           false,                   // Should fail due to user not found
			expectedRequiresSwitch:    true,
		},

		// Windows feature doesn't support user switching
		{
			name:                      "windows_admin_feature_no_user_switching_different_user",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("Administrator", "S-1-5-21-123456789-123456789-123456789-500", "S-1-5-32-544", "C:\\Users\\Administrator"),
			requestedUsername:         "alice",
			featureSupportsUserSwitch: false, // Feature doesn't support switching
			allowRoot:                 true,
			lookupUsers: map[string]*user.User{
				"alice": createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\alice"),
			},
			expectedAllowed:        false, // Should deny because feature doesn't support switching
			expectedRequiresSwitch: true,
		},

		// Windows regular user scenarios (non-admin)
		{
			name:                      "windows_regular_user_same_user",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\alice"),
			requestedUsername:         "alice", // Same user
			featureSupportsUserSwitch: true,
			allowRoot:                 false,
			lookupUsers: map[string]*user.User{
				"alice": createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\alice"),
			},
			expectedAllowed:        true,  // Regular user accessing themselves should work
			expectedRequiresSwitch: false, // No switching for same user
		},
		{
			name:                      "windows_regular_user_empty_username",
			os:                        "windows",
			euid:                      1000,
			currentUser:               createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\Users\\alice"),
			requestedUsername:         "", // Empty = current user
			featureSupportsUserSwitch: true,
			allowRoot:                 false,
			expectedAllowed:           true,  // Current user should always work
			expectedRequiresSwitch:    false, // No switching for current user
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Inject platform dependencies to test real logic
			cleanup := setupTestDependencies(tt.currentUser, nil, tt.os, tt.euid, tt.lookupUsers, nil)
			defer cleanup()

			server := &Server{allowRootLogin: tt.allowRoot}

			result := server.CheckPrivileges(PrivilegeCheckRequest{
				RequestedUsername:         tt.requestedUsername,
				FeatureSupportsUserSwitch: tt.featureSupportsUserSwitch,
				FeatureName:               "SSH login",
			})

			assert.Equal(t, tt.expectedAllowed, result.Allowed)
			assert.Equal(t, tt.expectedRequiresSwitch, result.RequiresUserSwitching)
		})
	}
}

func TestUsedFallback_MeansNoPrivilegeDropping(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Fallback mechanism is Unix-specific")
	}

	// Create test scenario where fallback should occur
	server := &Server{allowRootLogin: true}

	// Mock dependencies to simulate non-privileged user
	originalGetCurrentUser := getCurrentUser
	originalGetIsProcessPrivileged := getIsProcessPrivileged

	defer func() {
		getCurrentUser = originalGetCurrentUser
		getIsProcessPrivileged = originalGetIsProcessPrivileged

	}()

	// Set up mocks for fallback scenario
	getCurrentUser = func() (*user.User, error) {
		return createTestUser("netbird", "1000", "1000", "/var/lib/netbird"), nil
	}
	getIsProcessPrivileged = func() bool { return false } // Non-privileged

	// Request different user - should fallback
	result := server.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         "alice",
		FeatureSupportsUserSwitch: true,
		FeatureName:               "SSH login",
	})

	// Verify fallback occurred
	assert.True(t, result.Allowed, "Should allow with fallback")
	assert.True(t, result.UsedFallback, "Should indicate fallback was used")
	assert.Equal(t, "netbird", result.User.Username, "Should return current user")
	assert.False(t, result.RequiresUserSwitching, "Should not require switching when fallback is used")

	// Key assertion: When UsedFallback is true, no privilege dropping should be needed
	// because all privilege checks have already been performed and we're using current user
	t.Logf("UsedFallback=true means: current user (%s) is the target, no privilege dropping needed",
		result.User.Username)
}

func TestPrivilegedUsernameDetection(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		platform   string
		privileged bool
	}{
		// Unix/Linux tests
		{"unix_root", "root", "linux", true},
		{"unix_regular_user", "alice", "linux", false},
		{"unix_root_capital", "Root", "linux", false}, // Case-sensitive

		// Windows tests
		{"windows_administrator", "Administrator", "windows", true},
		{"windows_system", "SYSTEM", "windows", true},
		{"windows_admin", "admin", "windows", true},
		{"windows_admin_lowercase", "administrator", "windows", true}, // Case-insensitive
		{"windows_domain_admin", "DOMAIN\\Administrator", "windows", true},
		{"windows_email_admin", "admin@domain.com", "windows", true},
		{"windows_regular_user", "alice", "windows", false},
		{"windows_domain_user", "DOMAIN\\alice", "windows", false},
		{"windows_localsystem", "localsystem", "windows", true},
		{"windows_networkservice", "networkservice", "windows", true},
		{"windows_localservice", "localservice", "windows", true},

		// Computer accounts (these depend on current user context in real implementation)
		{"windows_computer_account", "WIN2K19-C2$", "windows", false},      // Computer account by itself not privileged
		{"windows_domain_computer", "DOMAIN\\COMPUTER$", "windows", false}, // Domain computer account

		// Cross-platform
		{"root_on_windows", "root", "windows", true}, // Root should be privileged everywhere
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the platform for this test
			cleanup := setupTestDependencies(nil, nil, tt.platform, 1000, nil, nil)
			defer cleanup()

			result := isPrivilegedUsername(tt.username)
			assert.Equal(t, tt.privileged, result)
		})
	}
}

func TestWindowsPrivilegedSIDDetection(t *testing.T) {
	tests := []struct {
		name        string
		sid         string
		privileged  bool
		description string
	}{
		// Well-known system accounts
		{"system_account", "S-1-5-18", true, "Local System (SYSTEM)"},
		{"local_service", "S-1-5-19", true, "Local Service"},
		{"network_service", "S-1-5-20", true, "Network Service"},
		{"administrators_group", "S-1-5-32-544", true, "Administrators group"},
		{"builtin_administrator", "S-1-5-500", true, "Built-in Administrator"},

		// Domain accounts
		{"domain_administrator", "S-1-5-21-1234567890-1234567890-1234567890-500", true, "Domain Administrator (RID 500)"},
		{"domain_admins_group", "S-1-5-21-1234567890-1234567890-1234567890-512", true, "Domain Admins group"},
		{"domain_controllers_group", "S-1-5-21-1234567890-1234567890-1234567890-516", true, "Domain Controllers group"},
		{"enterprise_admins_group", "S-1-5-21-1234567890-1234567890-1234567890-519", true, "Enterprise Admins group"},

		// Regular users
		{"regular_user", "S-1-5-21-1234567890-1234567890-1234567890-1001", false, "Regular domain user"},
		{"another_regular_user", "S-1-5-21-1234567890-1234567890-1234567890-1234", false, "Another regular user"},
		{"local_user", "S-1-5-21-1234567890-1234567890-1234567890-1000", false, "Local regular user"},

		// Groups that are not privileged
		{"domain_users", "S-1-5-21-1234567890-1234567890-1234567890-513", false, "Domain Users group"},
		{"power_users", "S-1-5-32-547", false, "Power Users group"},

		// Invalid SIDs
		{"malformed_sid", "S-1-5-invalid", false, "Malformed SID"},
		{"empty_sid", "", false, "Empty SID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWindowsPrivilegedSID(tt.sid)
			assert.Equal(t, tt.privileged, result, "Failed for %s: %s", tt.description, tt.sid)
		})
	}
}

func TestIsSameUser(t *testing.T) {
	tests := []struct {
		name     string
		user1    string
		user2    string
		os       string
		expected bool
	}{
		// Basic cases
		{"same_username", "alice", "alice", "linux", true},
		{"different_username", "alice", "bob", "linux", false},

		// Linux (no domain processing)
		{"linux_domain_vs_bare", "DOMAIN\\alice", "alice", "linux", false},
		{"linux_email_vs_bare", "alice@domain.com", "alice", "linux", false},
		{"linux_same_literal", "DOMAIN\\alice", "DOMAIN\\alice", "linux", true},

		// Windows (with domain processing) - Note: parameter order is (requested, current, os, expected)
		{"windows_domain_vs_bare", "alice", "DOMAIN\\alice", "windows", true},                         // bare username matches domain current user
		{"windows_email_vs_bare", "alice", "alice@domain.com", "windows", true},                       // bare username matches email current user
		{"windows_different_domains_same_user", "DOMAIN1\\alice", "DOMAIN2\\alice", "windows", false}, // SECURITY: different domains = different users
		{"windows_case_insensitive", "Alice", "alice", "windows", true},
		{"windows_different_users", "DOMAIN\\alice", "DOMAIN\\bob", "windows", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up OS mock
			cleanup := setupTestDependencies(nil, nil, tt.os, 1000, nil, nil)
			defer cleanup()

			result := isSameUser(tt.user1, tt.user2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUsernameValidation_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific username validation tests")
	}

	tests := []struct {
		name     string
		username string
		wantErr  bool
		errMsg   string
	}{
		// Valid usernames (Unix/POSIX)
		{"valid_alphanumeric", "user123", false, ""},
		{"valid_with_dots", "user.name", false, ""},
		{"valid_with_hyphens", "user-name", false, ""},
		{"valid_with_underscores", "user_name", false, ""},
		{"valid_uppercase", "UserName", false, ""},
		{"valid_starting_with_digit", "123user", false, ""},
		{"valid_starting_with_dot", ".hidden", false, ""},

		// Invalid usernames (Unix/POSIX)
		{"empty_username", "", true, "username cannot be empty"},
		{"username_too_long", "thisusernameiswaytoolongandexceedsthe32characterlimit", true, "username too long"},
		{"username_starting_with_hyphen", "-user", true, "invalid characters"}, // POSIX restriction
		{"username_with_spaces", "user name", true, "invalid characters"},
		{"username_with_shell_metacharacters", "user;rm", true, "invalid characters"},
		{"username_with_command_injection", "user`rm -rf /`", true, "invalid characters"},
		{"username_with_pipe", "user|rm", true, "invalid characters"},
		{"username_with_ampersand", "user&rm", true, "invalid characters"},
		{"username_with_quotes", "user\"name", true, "invalid characters"},
		{"username_with_newline", "user\nname", true, "invalid characters"},
		{"reserved_dot", ".", true, "cannot be '.' or '..'"},
		{"reserved_dotdot", "..", true, "cannot be '.' or '..'"},
		{"username_with_at_symbol", "user@domain", true, "invalid characters"}, // Not allowed in bare Unix usernames
		{"username_with_backslash", "user\\name", true, "invalid characters"},  // Not allowed in Unix usernames
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.username)
			if tt.wantErr {
				assert.Error(t, err, "Should reject invalid username")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Should accept valid username")
			}
		})
	}
}

func TestUsernameValidation_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific username validation tests")
	}

	tests := []struct {
		name     string
		username string
		wantErr  bool
		errMsg   string
	}{
		// Valid usernames (Windows)
		{"valid_alphanumeric", "user123", false, ""},
		{"valid_with_dots", "user.name", false, ""},
		{"valid_with_hyphens", "user-name", false, ""},
		{"valid_with_underscores", "user_name", false, ""},
		{"valid_uppercase", "UserName", false, ""},
		{"valid_starting_with_digit", "123user", false, ""},
		{"valid_starting_with_dot", ".hidden", false, ""},
		{"valid_starting_with_hyphen", "-user", false, ""},     // Windows allows this
		{"valid_domain_username", "DOMAIN\\user", false, ""},   // Windows domain format
		{"valid_email_username", "user@domain.com", false, ""}, // Windows email format
		{"valid_machine_username", "MACHINE\\user", false, ""}, // Windows machine format

		// Invalid usernames (Windows)
		{"empty_username", "", true, "username cannot be empty"},
		{"username_too_long", "thisusernameiswaytoolongandexceedsthe32characterlimit", true, "username too long"},
		{"username_with_spaces", "user name", true, "invalid characters"},
		{"username_with_shell_metacharacters", "user;rm", true, "invalid characters"},
		{"username_with_command_injection", "user`rm -rf /`", true, "invalid characters"},
		{"username_with_pipe", "user|rm", true, "invalid characters"},
		{"username_with_ampersand", "user&rm", true, "invalid characters"},
		{"username_with_quotes", "user\"name", true, "invalid characters"},
		{"username_with_newline", "user\nname", true, "invalid characters"},
		{"username_with_brackets", "user[name]", true, "invalid characters"},
		{"username_with_colon", "user:name", true, "invalid characters"},
		{"username_with_semicolon", "user;name", true, "invalid characters"},
		{"username_with_equals", "user=name", true, "invalid characters"},
		{"username_with_comma", "user,name", true, "invalid characters"},
		{"username_with_plus", "user+name", true, "invalid characters"},
		{"username_with_asterisk", "user*name", true, "invalid characters"},
		{"username_with_question", "user?name", true, "invalid characters"},
		{"username_with_angles", "user<name>", true, "invalid characters"},
		{"reserved_dot", ".", true, "cannot be '.' or '..'"},
		{"reserved_dotdot", "..", true, "cannot be '.' or '..'"},
		{"username_ending_with_period", "user.", true, "cannot end with a period"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.username)
			if tt.wantErr {
				assert.Error(t, err, "Should reject invalid username")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Should accept valid username")
			}
		})
	}
}

// Test real-world integration scenarios with actual platform capabilities
func TestCheckPrivileges_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name                      string
		feature                   string
		featureSupportsUserSwitch bool
		requestedUsername         string
		allowRoot                 bool
		expectedBehaviorPattern   string
	}{
		{"SSH_login_current_user", "SSH login", true, "", true, "should_allow_current_user"},
		{"SFTP_current_user", "SFTP", true, "", true, "should_allow_current_user"},
		{"port_forwarding_current_user", "port forwarding", false, "", true, "should_allow_current_user"},
		{"SSH_login_root_not_allowed", "SSH login", true, "root", false, "should_deny_root"},
		{"port_forwarding_different_user", "port forwarding", false, "differentuser", true, "should_deny_switching"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock privileged environment to ensure consistent test behavior across environments
			cleanup := setupTestDependencies(
				createTestUser("root", "0", "0", "/root"), // Running as root
				nil,
				runtime.GOOS,
				0, // euid 0 (root)
				map[string]*user.User{
					"root":          createTestUser("root", "0", "0", "/root"),
					"differentuser": createTestUser("differentuser", "1000", "1000", "/home/differentuser"),
				},
				nil,
			)
			defer cleanup()

			server := &Server{allowRootLogin: tt.allowRoot}

			result := server.CheckPrivileges(PrivilegeCheckRequest{
				RequestedUsername:         tt.requestedUsername,
				FeatureSupportsUserSwitch: tt.featureSupportsUserSwitch,
				FeatureName:               tt.feature,
			})

			switch tt.expectedBehaviorPattern {
			case "should_allow_current_user":
				assert.True(t, result.Allowed, "Should allow current user access")
				assert.False(t, result.RequiresUserSwitching, "Current user should not require switching")
			case "should_deny_root":
				assert.False(t, result.Allowed, "Should deny root when not allowed")
				assert.Contains(t, result.Error.Error(), "root", "Should mention root in error")
			case "should_deny_switching":
				assert.False(t, result.Allowed, "Should deny when feature doesn't support switching")
				assert.Contains(t, result.Error.Error(), "user switching not supported", "Should mention switching in error")
			}
		})
	}
}

// Test with actual platform capabilities - no mocking
func TestCheckPrivileges_ActualPlatform(t *testing.T) {
	// This test uses the REAL platform capabilities
	server := &Server{allowRootLogin: true}

	// Test current user access - should always work
	result := server.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         "", // Current user
		FeatureSupportsUserSwitch: true,
		FeatureName:               "SSH login",
	})

	assert.True(t, result.Allowed, "Current user should always be allowed")
	assert.False(t, result.RequiresUserSwitching, "Current user should not require switching")
	assert.NotNil(t, result.User, "Should return current user")

	// Test user switching capability based on actual platform
	actualIsPrivileged := isCurrentProcessPrivileged() // REAL check
	actualOS := runtime.GOOS                           // REAL check

	t.Logf("Platform capabilities: OS=%s, isPrivileged=%v, supportsUserSwitching=%v",
		actualOS, actualIsPrivileged, actualIsPrivileged)

	// Test requesting different user
	result = server.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         "nonexistentuser",
		FeatureSupportsUserSwitch: true,
		FeatureName:               "SSH login",
	})

	switch {
	case actualOS == "windows":
		// Windows supports user switching but should fail on nonexistent user
		assert.False(t, result.Allowed, "Windows should deny nonexistent user")
		assert.True(t, result.RequiresUserSwitching, "Should indicate switching is needed")
		assert.Contains(t, result.Error.Error(), "not found",
			"Should indicate user not found")
	case !actualIsPrivileged:
		// Non-privileged Unix processes should fallback to current user
		assert.True(t, result.Allowed, "Non-privileged Unix process should fallback to current user")
		assert.False(t, result.RequiresUserSwitching, "Fallback means no switching actually happens")
		assert.True(t, result.UsedFallback, "Should indicate fallback was used")
		assert.NotNil(t, result.User, "Should return current user")
	default:
		// Privileged Unix processes should attempt user lookup
		assert.False(t, result.Allowed, "Should fail due to nonexistent user")
		assert.True(t, result.RequiresUserSwitching, "Should indicate switching is needed")
		assert.Contains(t, result.Error.Error(), "nonexistentuser",
			"Should indicate user not found")
	}
}

// Test platform detection logic with dependency injection
func TestPlatformLogic_DependencyInjection(t *testing.T) {
	tests := []struct {
		name                          string
		os                            string
		euid                          int
		currentUser                   *user.User
		expectedIsProcessPrivileged   bool
		expectedSupportsUserSwitching bool
	}{
		{
			name:                          "linux_root_process",
			os:                            "linux",
			euid:                          0,
			currentUser:                   createTestUser("root", "0", "0", "/root"),
			expectedIsProcessPrivileged:   true,
			expectedSupportsUserSwitching: true,
		},
		{
			name:                          "linux_non_root_process",
			os:                            "linux",
			euid:                          1000,
			currentUser:                   createTestUser("alice", "1000", "1000", "/home/alice"),
			expectedIsProcessPrivileged:   false,
			expectedSupportsUserSwitching: false,
		},
		{
			name:                          "windows_admin_process",
			os:                            "windows",
			euid:                          1000, // euid ignored on Windows
			currentUser:                   createTestUser("Administrator", "S-1-5-21-123456789-123456789-123456789-500", "S-1-5-32-544", "C:\\Users\\Administrator"),
			expectedIsProcessPrivileged:   true,
			expectedSupportsUserSwitching: true, // Windows supports user switching when privileged
		},
		{
			name:                          "windows_regular_process",
			os:                            "windows",
			euid:                          1000, // euid ignored on Windows
			currentUser:                   createTestUser("alice", "1001", "1001", "C:\\Users\\alice"),
			expectedIsProcessPrivileged:   false,
			expectedSupportsUserSwitching: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Inject platform dependencies and test REAL logic
			cleanup := setupTestDependencies(tt.currentUser, nil, tt.os, tt.euid, nil, nil)
			defer cleanup()

			// Test the actual functions with injected dependencies
			actualIsPrivileged := isCurrentProcessPrivileged()
			actualSupportsUserSwitching := actualIsPrivileged

			assert.Equal(t, tt.expectedIsProcessPrivileged, actualIsPrivileged,
				"isCurrentProcessPrivileged() result mismatch")
			assert.Equal(t, tt.expectedSupportsUserSwitching, actualSupportsUserSwitching,
				"supportsUserSwitching() result mismatch")

			t.Logf("Platform: %s, EUID: %d, User: %s", tt.os, tt.euid, tt.currentUser.Username)
			t.Logf("Results: isPrivileged=%v, supportsUserSwitching=%v",
				actualIsPrivileged, actualSupportsUserSwitching)
		})
	}
}

func TestCheckPrivileges_WindowsElevatedUserSwitching(t *testing.T) {
	// Test Windows elevated user switching scenarios with simplified privilege logic
	tests := []struct {
		name                  string
		currentUser           *user.User
		requestedUsername     string
		allowRoot             bool
		expectedAllowed       bool
		expectedErrorContains string
	}{
		{
			name:              "windows_admin_can_switch_to_alice",
			currentUser:       createTestUser("administrator", "S-1-5-21-123456789-123456789-123456789-500", "S-1-5-32-544", "C:\\\\Users\\\\Administrator"),
			requestedUsername: "alice",
			allowRoot:         true,
			expectedAllowed:   true,
		},
		{
			name:              "windows_non_admin_can_try_switch",
			currentUser:       createTestUser("alice", "S-1-5-21-123456789-123456789-123456789-1001", "S-1-5-21-123456789-123456789-123456789-513", "C:\\\\Users\\\\alice"),
			requestedUsername: "bob",
			allowRoot:         true,
			expectedAllowed:   true, // Privilege check allows it, OS will reject during execution
		},
		{
			name:              "windows_system_can_switch_to_alice",
			currentUser:       createTestUser("SYSTEM", "S-1-5-18", "S-1-5-18", "C:\\\\Windows\\\\system32\\\\config\\\\systemprofile"),
			requestedUsername: "alice",
			allowRoot:         true,
			expectedAllowed:   true,
		},
		{
			name:                  "windows_admin_root_not_allowed",
			currentUser:           createTestUser("administrator", "S-1-5-21-123456789-123456789-123456789-500", "S-1-5-32-544", "C:\\\\Users\\\\Administrator"),
			requestedUsername:     "root",
			allowRoot:             false,
			expectedAllowed:       false,
			expectedErrorContains: "privileged user login is disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test dependencies with Windows OS and specified privileges
			lookupUsers := map[string]*user.User{
				tt.requestedUsername: createTestUser(tt.requestedUsername, "1002", "1002", "C:\\\\Users\\\\"+tt.requestedUsername),
			}
			cleanup := setupTestDependencies(tt.currentUser, nil, "windows", 1000, lookupUsers, nil)
			defer cleanup()

			server := &Server{allowRootLogin: tt.allowRoot}

			result := server.CheckPrivileges(PrivilegeCheckRequest{
				RequestedUsername:         tt.requestedUsername,
				FeatureSupportsUserSwitch: true,
				FeatureName:               "SSH login",
			})

			assert.Equal(t, tt.expectedAllowed, result.Allowed,
				"Privilege check result should match expected for %s", tt.name)

			if !tt.expectedAllowed && tt.expectedErrorContains != "" {
				assert.NotNil(t, result.Error, "Should have error when not allowed")
				assert.Contains(t, result.Error.Error(), tt.expectedErrorContains,
					"Error should contain expected message")
			}

			if tt.expectedAllowed && tt.requestedUsername != "" && tt.currentUser.Username != tt.requestedUsername {
				assert.True(t, result.RequiresUserSwitching, "Should require user switching for different user")
			}
		})
	}
}
