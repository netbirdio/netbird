package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/sshauth"
)

func TestAuthorizer_Authorize_UserNotInList(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up authorized users list with one user
	authorizedUserHash, err := sshauth.HashUserID("authorized-user")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{authorizedUserHash},
		MachineUsers:    map[string][]uint32{},
	}
	authorizer.Update(config)

	// Try to authorize a different user
	_, err = authorizer.Authorize("unauthorized-user", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotAuthorized)
}

func TestAuthorizer_Authorize_UserInList_NoMachineUserRestrictions(t *testing.T) {
	authorizer := NewAuthorizer()

	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash, user2Hash},
		MachineUsers:    map[string][]uint32{}, // Empty = deny all (fail closed)
	}
	authorizer.Update(config)

	// All attempts should fail when no machine user mappings exist (fail closed)
	_, err = authorizer.Authorize("user1", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)

	_, err = authorizer.Authorize("user2", "admin")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)

	_, err = authorizer.Authorize("user1", "postgres")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)
}

func TestAuthorizer_Authorize_UserInList_WithMachineUserMapping_Allowed(t *testing.T) {
	authorizer := NewAuthorizer()

	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)
	user3Hash, err := sshauth.HashUserID("user3")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash, user2Hash, user3Hash},
		MachineUsers: map[string][]uint32{
			"root":     {0, 1}, // user1 and user2 can access root
			"postgres": {1, 2}, // user2 and user3 can access postgres
			"admin":    {0},    // only user1 can access admin
		},
	}
	authorizer.Update(config)

	// user1 (index 0) should access root and admin
	_, err = authorizer.Authorize("user1", "root")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user1", "admin")
	assert.NoError(t, err)

	// user2 (index 1) should access root and postgres
	_, err = authorizer.Authorize("user2", "root")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user2", "postgres")
	assert.NoError(t, err)

	// user3 (index 2) should access postgres
	_, err = authorizer.Authorize("user3", "postgres")
	assert.NoError(t, err)
}

func TestAuthorizer_Authorize_UserInList_WithMachineUserMapping_Denied(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up authorized users list
	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)
	user3Hash, err := sshauth.HashUserID("user3")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash, user2Hash, user3Hash},
		MachineUsers: map[string][]uint32{
			"root":     {0, 1}, // user1 and user2 can access root
			"postgres": {1, 2}, // user2 and user3 can access postgres
			"admin":    {0},    // only user1 can access admin
		},
	}
	authorizer.Update(config)

	// user1 (index 0) should NOT access postgres
	_, err = authorizer.Authorize("user1", "postgres")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotMappedToOSUser)

	// user2 (index 1) should NOT access admin
	_, err = authorizer.Authorize("user2", "admin")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotMappedToOSUser)

	// user3 (index 2) should NOT access root
	_, err = authorizer.Authorize("user3", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotMappedToOSUser)

	// user3 (index 2) should NOT access admin
	_, err = authorizer.Authorize("user3", "admin")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotMappedToOSUser)
}

func TestAuthorizer_Authorize_UserInList_OSUserNotInMapping(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up authorized users list
	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash},
		MachineUsers: map[string][]uint32{
			"root": {0}, // only root is mapped
		},
	}
	authorizer.Update(config)

	// user1 should NOT access an unmapped OS user (fail closed)
	_, err = authorizer.Authorize("user1", "postgres")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)
}

func TestAuthorizer_Authorize_EmptyJWTUserID(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up authorized users list
	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash},
		MachineUsers:    map[string][]uint32{},
	}
	authorizer.Update(config)

	// Empty user ID should fail
	_, err = authorizer.Authorize("", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyUserID)
}

func TestAuthorizer_Authorize_MultipleUsersInList(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up multiple authorized users
	userHashes := make([]sshauth.UserIDHash, 10)
	for i := 0; i < 10; i++ {
		hash, err := sshauth.HashUserID("user" + string(rune('0'+i)))
		require.NoError(t, err)
		userHashes[i] = hash
	}

	// Create machine user mapping for all users
	rootIndexes := make([]uint32, 10)
	for i := 0; i < 10; i++ {
		rootIndexes[i] = uint32(i)
	}

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: userHashes,
		MachineUsers: map[string][]uint32{
			"root": rootIndexes,
		},
	}
	authorizer.Update(config)

	// All users should be authorized for root
	for i := 0; i < 10; i++ {
		_, err := authorizer.Authorize("user"+string(rune('0'+i)), "root")
		assert.NoError(t, err, "user%d should be authorized", i)
	}

	// User not in list should fail
	_, err := authorizer.Authorize("unknown-user", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotAuthorized)
}

func TestAuthorizer_Update_ClearsConfiguration(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up initial configuration
	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash},
		MachineUsers:    map[string][]uint32{"root": {0}},
	}
	authorizer.Update(config)

	// user1 should be authorized
	_, err = authorizer.Authorize("user1", "root")
	assert.NoError(t, err)

	// Clear configuration
	authorizer.Update(nil)

	// user1 should no longer be authorized
	_, err = authorizer.Authorize("user1", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotAuthorized)
}

func TestAuthorizer_Update_EmptyMachineUsersListEntries(t *testing.T) {
	authorizer := NewAuthorizer()

	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)

	// Machine users with empty index lists should be filtered out
	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash},
		MachineUsers: map[string][]uint32{
			"root":     {0},
			"postgres": {},  // empty list - should be filtered out
			"admin":    nil, // nil list - should be filtered out
		},
	}
	authorizer.Update(config)

	// root should work
	_, err = authorizer.Authorize("user1", "root")
	assert.NoError(t, err)

	// postgres should fail (no mapping)
	_, err = authorizer.Authorize("user1", "postgres")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)

	// admin should fail (no mapping)
	_, err = authorizer.Authorize("user1", "admin")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)
}

func TestAuthorizer_CustomUserIDClaim(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up with custom user ID claim
	user1Hash, err := sshauth.HashUserID("user@example.com")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     "email",
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash},
		MachineUsers: map[string][]uint32{
			"root": {0},
		},
	}
	authorizer.Update(config)

	// Verify the custom claim is set
	assert.Equal(t, "email", authorizer.GetUserIDClaim())

	// Authorize with email as user ID
	_, err = authorizer.Authorize("user@example.com", "root")
	assert.NoError(t, err)
}

func TestAuthorizer_DefaultUserIDClaim(t *testing.T) {
	authorizer := NewAuthorizer()

	// Verify default claim
	assert.Equal(t, DefaultUserIDClaim, authorizer.GetUserIDClaim())
	assert.Equal(t, "sub", authorizer.GetUserIDClaim())

	// Set up with empty user ID claim (should use default)
	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     "", // empty - should use default
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash},
		MachineUsers:    map[string][]uint32{},
	}
	authorizer.Update(config)

	// Should fall back to default
	assert.Equal(t, DefaultUserIDClaim, authorizer.GetUserIDClaim())
}

func TestAuthorizer_MachineUserMapping_LargeIndexes(t *testing.T) {
	authorizer := NewAuthorizer()

	// Create a large authorized users list
	const numUsers = 1000
	userHashes := make([]sshauth.UserIDHash, numUsers)
	for i := 0; i < numUsers; i++ {
		hash, err := sshauth.HashUserID("user" + string(rune(i)))
		require.NoError(t, err)
		userHashes[i] = hash
	}

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: userHashes,
		MachineUsers: map[string][]uint32{
			"root": {0, 500, 999}, // first, middle, and last user
		},
	}
	authorizer.Update(config)

	// First user should have access
	_, err := authorizer.Authorize("user"+string(rune(0)), "root")
	assert.NoError(t, err)

	// Middle user should have access
	_, err = authorizer.Authorize("user"+string(rune(500)), "root")
	assert.NoError(t, err)

	// Last user should have access
	_, err = authorizer.Authorize("user"+string(rune(999)), "root")
	assert.NoError(t, err)

	// User not in mapping should NOT have access
	_, err = authorizer.Authorize("user"+string(rune(100)), "root")
	assert.Error(t, err)
}

func TestAuthorizer_ConcurrentAuthorization(t *testing.T) {
	authorizer := NewAuthorizer()

	// Set up authorized users
	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)

	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash, user2Hash},
		MachineUsers: map[string][]uint32{
			"root": {0, 1},
		},
	}
	authorizer.Update(config)

	// Test concurrent authorization calls (should be safe to read concurrently)
	const numGoroutines = 100
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			user := "user1"
			if idx%2 == 0 {
				user = "user2"
			}
			_, err := authorizer.Authorize(user, "root")
			errChan <- err
		}(i)
	}

	// Wait for all goroutines to complete and collect errors
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		assert.NoError(t, err)
	}
}

func TestAuthorizer_Wildcard_AllowsAllAuthorizedUsers(t *testing.T) {
	authorizer := NewAuthorizer()

	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)
	user3Hash, err := sshauth.HashUserID("user3")
	require.NoError(t, err)

	// Configure with wildcard - all authorized users can access any OS user
	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash, user2Hash, user3Hash},
		MachineUsers: map[string][]uint32{
			"*": {0, 1, 2}, // wildcard with all user indexes
		},
	}
	authorizer.Update(config)

	// All authorized users should be able to access any OS user
	_, err = authorizer.Authorize("user1", "root")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user2", "postgres")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user3", "admin")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user1", "ubuntu")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user2", "nginx")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user3", "docker")
	assert.NoError(t, err)
}

func TestAuthorizer_Wildcard_UnauthorizedUserStillDenied(t *testing.T) {
	authorizer := NewAuthorizer()

	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)

	// Configure with wildcard
	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash},
		MachineUsers: map[string][]uint32{
			"*": {0},
		},
	}
	authorizer.Update(config)

	// user1 should have access
	_, err = authorizer.Authorize("user1", "root")
	assert.NoError(t, err)

	// Unauthorized user should still be denied even with wildcard
	_, err = authorizer.Authorize("unauthorized-user", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotAuthorized)
}

func TestAuthorizer_Wildcard_TakesPrecedenceOverSpecificMappings(t *testing.T) {
	authorizer := NewAuthorizer()

	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)

	// Configure with both wildcard and specific mappings
	// Wildcard takes precedence for users in the wildcard index list
	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash, user2Hash},
		MachineUsers: map[string][]uint32{
			"*":    {0, 1}, // wildcard for both users
			"root": {0},    // specific mapping that would normally restrict to user1 only
		},
	}
	authorizer.Update(config)

	// Both users should be able to access root via wildcard (takes precedence over specific mapping)
	_, err = authorizer.Authorize("user1", "root")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user2", "root")
	assert.NoError(t, err)

	// Both users should be able to access any other OS user via wildcard
	_, err = authorizer.Authorize("user1", "postgres")
	assert.NoError(t, err)

	_, err = authorizer.Authorize("user2", "admin")
	assert.NoError(t, err)
}

func TestAuthorizer_NoWildcard_SpecificMappingsOnly(t *testing.T) {
	authorizer := NewAuthorizer()

	user1Hash, err := sshauth.HashUserID("user1")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)

	// Configure WITHOUT wildcard - only specific mappings
	config := &Config{
		UserIDClaim:     DefaultUserIDClaim,
		AuthorizedUsers: []sshauth.UserIDHash{user1Hash, user2Hash},
		MachineUsers: map[string][]uint32{
			"root":     {0}, // only user1
			"postgres": {1}, // only user2
		},
	}
	authorizer.Update(config)

	// user1 can access root
	_, err = authorizer.Authorize("user1", "root")
	assert.NoError(t, err)

	// user2 can access postgres
	_, err = authorizer.Authorize("user2", "postgres")
	assert.NoError(t, err)

	// user1 cannot access postgres
	_, err = authorizer.Authorize("user1", "postgres")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotMappedToOSUser)

	// user2 cannot access root
	_, err = authorizer.Authorize("user2", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotMappedToOSUser)

	// Neither can access unmapped OS users
	_, err = authorizer.Authorize("user1", "admin")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)

	_, err = authorizer.Authorize("user2", "admin")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)
}

func TestAuthorizer_Wildcard_WithPartialIndexes_AllowsAllUsers(t *testing.T) {
	// This test covers the scenario where wildcard exists with limited indexes.
	// Only users whose indexes are in the wildcard list can access any OS user via wildcard.
	// Other users can only access OS users they are explicitly mapped to.
	authorizer := NewAuthorizer()

	// Create two authorized user hashes (simulating the base64-encoded hashes in the config)
	wasmHash, err := sshauth.HashUserID("wasm")
	require.NoError(t, err)
	user2Hash, err := sshauth.HashUserID("user2")
	require.NoError(t, err)

	// Configure with wildcard having only index 0, and specific mappings for other OS users
	config := &Config{
		UserIDClaim:     "sub",
		AuthorizedUsers: []sshauth.UserIDHash{wasmHash, user2Hash},
		MachineUsers: map[string][]uint32{
			"*":     {0}, // wildcard with only index 0 - only wasm has wildcard access
			"alice": {1}, // specific mapping for user2
			"bob":   {1}, // specific mapping for user2
		},
	}
	authorizer.Update(config)

	// wasm (index 0) should access any OS user via wildcard
	_, err = authorizer.Authorize("wasm", "root")
	assert.NoError(t, err, "wasm should access root via wildcard")

	_, err = authorizer.Authorize("wasm", "alice")
	assert.NoError(t, err, "wasm should access alice via wildcard")

	_, err = authorizer.Authorize("wasm", "bob")
	assert.NoError(t, err, "wasm should access bob via wildcard")

	_, err = authorizer.Authorize("wasm", "postgres")
	assert.NoError(t, err, "wasm should access postgres via wildcard")

	// user2 (index 1) should only access alice and bob (explicitly mapped), NOT root or postgres
	_, err = authorizer.Authorize("user2", "alice")
	assert.NoError(t, err, "user2 should access alice via explicit mapping")

	_, err = authorizer.Authorize("user2", "bob")
	assert.NoError(t, err, "user2 should access bob via explicit mapping")

	_, err = authorizer.Authorize("user2", "root")
	assert.Error(t, err, "user2 should NOT access root (not in wildcard indexes)")
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)

	_, err = authorizer.Authorize("user2", "postgres")
	assert.Error(t, err, "user2 should NOT access postgres (not explicitly mapped)")
	assert.ErrorIs(t, err, ErrNoMachineUserMapping)

	// Unauthorized user should still be denied
	_, err = authorizer.Authorize("user3", "root")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserNotAuthorized, "unauthorized user should be denied")
}
