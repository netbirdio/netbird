package testutil

import (
	"os/user"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserCurrentBehavior validates user.Current() behavior on Windows.
// When running as SYSTEM on a domain-joined machine, user.Current() returns:
// - Username: Computer account name (e.g., "DOMAIN\MACHINE$")
// - SID: SYSTEM SID (S-1-5-18)
func TestUserCurrentBehavior(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user")

	t.Logf("Current user - Username: %s, SID: %s", currentUser.Username, currentUser.Uid)

	// When running as SYSTEM, validate expected behavior
	if currentUser.Uid == "S-1-5-18" {
		t.Run("SYSTEM_account_behavior", func(t *testing.T) {
			// SID must be S-1-5-18 for SYSTEM
			require.Equal(t, "S-1-5-18", currentUser.Uid,
				"SYSTEM account must have SID S-1-5-18")

			// Username can be either "NT AUTHORITY\SYSTEM" (standalone)
			// or "DOMAIN\MACHINE$" (domain-joined)
			username := currentUser.Username
			isNTAuthority := strings.Contains(strings.ToUpper(username), "NT AUTHORITY")
			isComputerAccount := strings.HasSuffix(username, "$")

			assert.True(t, isNTAuthority || isComputerAccount,
				"Username should be either 'NT AUTHORITY\\SYSTEM' or computer account (ending with $), got: %s",
				username)

			if isComputerAccount {
				t.Logf("SYSTEM as computer account: %s", username)
			} else if isNTAuthority {
				t.Logf("SYSTEM as NT AUTHORITY\\SYSTEM")
			}
		})
	}

	// Validate that IsSystemAccount correctly identifies system accounts
	t.Run("IsSystemAccount_validation", func(t *testing.T) {
		// Test with current user if it's a system account
		if currentUser.Uid == "S-1-5-18" || // SYSTEM
			currentUser.Uid == "S-1-5-19" || // LOCAL SERVICE
			currentUser.Uid == "S-1-5-20" { // NETWORK SERVICE

			result := IsSystemAccount(currentUser.Username)
			assert.True(t, result,
				"IsSystemAccount should recognize system account: %s (SID: %s)",
				currentUser.Username, currentUser.Uid)
		}

		// Test explicit cases
		testCases := []struct {
			username string
			expected bool
			reason   string
		}{
			{"NT AUTHORITY\\SYSTEM", true, "NT AUTHORITY\\SYSTEM"},
			{"system", true, "system"},
			{"SYSTEM", true, "SYSTEM (case insensitive)"},
			{"NT AUTHORITY\\LOCAL SERVICE", true, "LOCAL SERVICE"},
			{"NT AUTHORITY\\NETWORK SERVICE", true, "NETWORK SERVICE"},
			{"DOMAIN\\MACHINE$", true, "computer account (ends with $)"},
			{"WORKGROUP\\WIN2K19-C2$", true, "computer account (ends with $)"},
			{"Administrator", false, "Administrator is not a system account"},
			{"alice", false, "regular user"},
			{"DOMAIN\\alice", false, "domain user"},
		}

		for _, tc := range testCases {
			t.Run(tc.username, func(t *testing.T) {
				result := IsSystemAccount(tc.username)
				assert.Equal(t, tc.expected, result,
					"IsSystemAccount(%q) should be %v because: %s",
					tc.username, tc.expected, tc.reason)
			})
		}
	})
}

// TestComputerAccountDetection validates computer account detection.
func TestComputerAccountDetection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	computerAccounts := []string{
		"MACHINE$",
		"WIN2K19-C2$",
		"DOMAIN\\MACHINE$",
		"WORKGROUP\\SERVER$",
		"server.domain.com$",
	}

	for _, account := range computerAccounts {
		t.Run(account, func(t *testing.T) {
			result := IsSystemAccount(account)
			assert.True(t, result,
				"Computer account %q should be recognized as system account", account)
		})
	}
}
