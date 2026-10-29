package testutil

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var testCreatedUsers = make(map[string]bool)
var testUsersToCleanup []string

// GetTestUsername returns an appropriate username for testing
func GetTestUsername(t *testing.T) string {
	if runtime.GOOS == "windows" {
		currentUser, err := user.Current()
		require.NoError(t, err, "Should be able to get current user")

		if IsSystemAccount(currentUser.Username) {
			if IsCI() {
				if testUser := GetOrCreateTestUser(t); testUser != "" {
					return testUser
				}
			} else {
				if _, err := user.Lookup("Administrator"); err == nil {
					return "Administrator"
				}
				if testUser := GetOrCreateTestUser(t); testUser != "" {
					return testUser
				}
			}
		}
		return currentUser.Username
	}

	currentUser, err := user.Current()
	require.NoError(t, err, "Should be able to get current user")
	return currentUser.Username
}

// IsCI checks if we're running in a CI environment
func IsCI() bool {
	if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("CI") == "true" {
		return true
	}

	hostname, err := os.Hostname()
	if err == nil && strings.HasPrefix(hostname, "runner") {
		return true
	}

	return false
}

// IsSystemAccount checks if the user is a system account that can't authenticate
func IsSystemAccount(username string) bool {
	systemAccounts := []string{
		"system",
		"NT AUTHORITY\\SYSTEM",
		"NT AUTHORITY\\LOCAL SERVICE",
		"NT AUTHORITY\\NETWORK SERVICE",
	}

	for _, sysAccount := range systemAccounts {
		if strings.EqualFold(username, sysAccount) {
			return true
		}
	}

	return strings.HasSuffix(username, "$")
}

// RegisterTestUserCleanup registers a test user for cleanup
func RegisterTestUserCleanup(username string) {
	if !testCreatedUsers[username] {
		testCreatedUsers[username] = true
		testUsersToCleanup = append(testUsersToCleanup, username)
	}
}

// CleanupTestUsers removes all created test users
func CleanupTestUsers() {
	for _, username := range testUsersToCleanup {
		RemoveWindowsTestUser(username)
	}
	testUsersToCleanup = nil
	testCreatedUsers = make(map[string]bool)
}

// GetOrCreateTestUser creates a test user on Windows if needed
func GetOrCreateTestUser(t *testing.T) string {
	testUsername := "netbird-test-user"

	if _, err := user.Lookup(testUsername); err == nil {
		return testUsername
	}

	if CreateWindowsTestUser(t, testUsername) {
		RegisterTestUserCleanup(testUsername)
		return testUsername
	}

	return ""
}

// RemoveWindowsTestUser removes a local user on Windows using PowerShell
func RemoveWindowsTestUser(username string) {
	if runtime.GOOS != "windows" {
		return
	}

	psCmd := fmt.Sprintf(`
		try {
			Remove-LocalUser -Name "%s" -ErrorAction Stop
			Write-Output "User removed successfully"
		} catch {
			if ($_.Exception.Message -like "*cannot be found*") {
				Write-Output "User not found (already removed)"
			} else {
				Write-Error $_.Exception.Message
			}
		}
	`, username)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("Failed to remove test user %s: %v, output: %s", username, err, string(output))
	} else {
		log.Printf("Test user %s cleanup result: %s", username, string(output))
	}
}

// CreateWindowsTestUser creates a local user on Windows using PowerShell
func CreateWindowsTestUser(t *testing.T, username string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	psCmd := fmt.Sprintf(`
		try {
			$password = ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force
			New-LocalUser -Name "%s" -Password $password -Description "NetBird test user" -UserMayNotChangePassword -PasswordNeverExpires
			Add-LocalGroupMember -Group "Users" -Member "%s"
			Write-Output "User created successfully"
		} catch {
			if ($_.Exception.Message -like "*already exists*") {
				Write-Output "User already exists"
			} else {
				Write-Error $_.Exception.Message
				exit 1
			}
		}
	`, username, username)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("Failed to create test user: %v, output: %s", err, string(output))
		return false
	}

	t.Logf("Test user creation result: %s", string(output))
	return true
}
