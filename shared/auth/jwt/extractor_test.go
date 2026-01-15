package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimsExtractor_ToUserAuth_ExtractsEmailAndName(t *testing.T) {
	tests := []struct {
		name           string
		claims         jwt.MapClaims
		userIDClaim    string
		audience       string
		expectedUserID string
		expectedEmail  string
		expectedName   string
		expectError    bool
	}{
		{
			name: "extracts email and name from standard claims",
			claims: jwt.MapClaims{
				"sub":   "user-123",
				"email": "test@example.com",
				"name":  "Test User",
			},
			userIDClaim:    "sub",
			expectedUserID: "user-123",
			expectedEmail:  "test@example.com",
			expectedName:   "Test User",
		},
		{
			name: "extracts Dex encoded user ID",
			claims: jwt.MapClaims{
				"sub":   "CiQ3YWFkOGMwNS0zMjg3LTQ3M2YtYjQyYS0zNjU1MDRiZjI1ZTcSBWxvY2Fs",
				"email": "dex-user@example.com",
				"name":  "Dex User",
			},
			userIDClaim:    "sub",
			expectedUserID: "CiQ3YWFkOGMwNS0zMjg3LTQ3M2YtYjQyYS0zNjU1MDRiZjI1ZTcSBWxvY2Fs",
			expectedEmail:  "dex-user@example.com",
			expectedName:   "Dex User",
		},
		{
			name: "handles missing email claim",
			claims: jwt.MapClaims{
				"sub":  "user-456",
				"name": "User Without Email",
			},
			userIDClaim:    "sub",
			expectedUserID: "user-456",
			expectedEmail:  "",
			expectedName:   "User Without Email",
		},
		{
			name: "handles missing name claim",
			claims: jwt.MapClaims{
				"sub":   "user-789",
				"email": "noname@example.com",
			},
			userIDClaim:    "sub",
			expectedUserID: "user-789",
			expectedEmail:  "noname@example.com",
			expectedName:   "",
		},
		{
			name: "handles missing both email and name",
			claims: jwt.MapClaims{
				"sub": "user-minimal",
			},
			userIDClaim:    "sub",
			expectedUserID: "user-minimal",
			expectedEmail:  "",
			expectedName:   "",
		},
		{
			name: "extracts preferred_username",
			claims: jwt.MapClaims{
				"sub":                "user-pref",
				"email":              "pref@example.com",
				"name":               "Preferred User",
				"preferred_username": "prefuser",
			},
			userIDClaim:    "sub",
			expectedUserID: "user-pref",
			expectedEmail:  "pref@example.com",
			expectedName:   "Preferred User",
		},
		{
			name: "fails when user ID claim is empty",
			claims: jwt.MapClaims{
				"email": "test@example.com",
				"name":  "Test User",
			},
			userIDClaim: "sub",
			expectError: true,
		},
		{
			name: "uses custom user ID claim",
			claims: jwt.MapClaims{
				"user_id": "custom-user-id",
				"email":   "custom@example.com",
				"name":    "Custom User",
			},
			userIDClaim:    "user_id",
			expectedUserID: "custom-user-id",
			expectedEmail:  "custom@example.com",
			expectedName:   "Custom User",
		},
		{
			name: "extracts account ID with audience prefix",
			claims: jwt.MapClaims{
				"sub":                                  "user-with-account",
				"email":                                "account@example.com",
				"name":                                 "Account User",
				"https://api.netbird.io/wt_account_id": "account-123",
				"https://api.netbird.io/wt_account_domain": "example.com",
			},
			userIDClaim:    "sub",
			audience:       "https://api.netbird.io",
			expectedUserID: "user-with-account",
			expectedEmail:  "account@example.com",
			expectedName:   "Account User",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create extractor with options
			opts := []ClaimsExtractorOption{}
			if tt.userIDClaim != "" {
				opts = append(opts, WithUserIDClaim(tt.userIDClaim))
			}
			if tt.audience != "" {
				opts = append(opts, WithAudience(tt.audience))
			}
			extractor := NewClaimsExtractor(opts...)

			// Create a mock token with the claims
			token := &jwt.Token{
				Claims: tt.claims,
			}

			// Extract user auth
			userAuth, err := extractor.ToUserAuth(token)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedUserID, userAuth.UserId)
			assert.Equal(t, tt.expectedEmail, userAuth.Email)
			assert.Equal(t, tt.expectedName, userAuth.Name)
		})
	}
}

func TestClaimsExtractor_ToUserAuth_PreferredUsername(t *testing.T) {
	extractor := NewClaimsExtractor(WithUserIDClaim("sub"))

	claims := jwt.MapClaims{
		"sub":                "user-123",
		"email":              "test@example.com",
		"name":               "Test User",
		"preferred_username": "testuser",
	}

	token := &jwt.Token{Claims: claims}

	userAuth, err := extractor.ToUserAuth(token)
	require.NoError(t, err)

	assert.Equal(t, "user-123", userAuth.UserId)
	assert.Equal(t, "test@example.com", userAuth.Email)
	assert.Equal(t, "Test User", userAuth.Name)
	assert.Equal(t, "testuser", userAuth.PreferredName)
}

func TestClaimsExtractor_ToUserAuth_LastLogin(t *testing.T) {
	extractor := NewClaimsExtractor(
		WithUserIDClaim("sub"),
		WithAudience("https://api.netbird.io"),
	)

	expectedTime := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	claims := jwt.MapClaims{
		"sub":                                  "user-123",
		"email":                                "test@example.com",
		"https://api.netbird.io/nb_last_login": expectedTime.Format(time.RFC3339),
	}

	token := &jwt.Token{Claims: claims}

	userAuth, err := extractor.ToUserAuth(token)
	require.NoError(t, err)

	assert.Equal(t, expectedTime, userAuth.LastLogin)
}

func TestClaimsExtractor_ToUserAuth_Invited(t *testing.T) {
	extractor := NewClaimsExtractor(
		WithUserIDClaim("sub"),
		WithAudience("https://api.netbird.io"),
	)

	claims := jwt.MapClaims{
		"sub":                               "user-123",
		"email":                             "invited@example.com",
		"https://api.netbird.io/nb_invited": true,
	}

	token := &jwt.Token{Claims: claims}

	userAuth, err := extractor.ToUserAuth(token)
	require.NoError(t, err)

	assert.True(t, userAuth.Invited)
}

func TestClaimsExtractor_ToGroups(t *testing.T) {
	extractor := NewClaimsExtractor(WithUserIDClaim("sub"))

	tests := []struct {
		name           string
		claims         jwt.MapClaims
		groupClaimName string
		expectedGroups []string
	}{
		{
			name: "extracts groups from claim",
			claims: jwt.MapClaims{
				"sub":    "user-123",
				"groups": []interface{}{"admin", "users", "developers"},
			},
			groupClaimName: "groups",
			expectedGroups: []string{"admin", "users", "developers"},
		},
		{
			name: "returns empty slice when claim missing",
			claims: jwt.MapClaims{
				"sub": "user-123",
			},
			groupClaimName: "groups",
			expectedGroups: []string{},
		},
		{
			name: "handles custom claim name",
			claims: jwt.MapClaims{
				"sub":        "user-123",
				"user_roles": []interface{}{"role1", "role2"},
			},
			groupClaimName: "user_roles",
			expectedGroups: []string{"role1", "role2"},
		},
		{
			name: "filters non-string values",
			claims: jwt.MapClaims{
				"sub":    "user-123",
				"groups": []interface{}{"admin", 123, "users", true},
			},
			groupClaimName: "groups",
			expectedGroups: []string{"admin", "users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{Claims: tt.claims}
			groups := extractor.ToGroups(token, tt.groupClaimName)
			assert.Equal(t, tt.expectedGroups, groups)
		})
	}
}

func TestClaimsExtractor_DefaultUserIDClaim(t *testing.T) {
	// When no user ID claim is specified, it should default to "sub"
	extractor := NewClaimsExtractor()

	claims := jwt.MapClaims{
		"sub":   "default-user-id",
		"email": "default@example.com",
	}

	token := &jwt.Token{Claims: claims}

	userAuth, err := extractor.ToUserAuth(token)
	require.NoError(t, err)

	assert.Equal(t, "default-user-id", userAuth.UserId)
}

func TestClaimsExtractor_DexUserIDFormat(t *testing.T) {
	// Test that the extractor correctly handles Dex's encoded user ID format
	// Dex encodes user IDs as base64(protobuf{user_id, connector_id})
	extractor := NewClaimsExtractor(WithUserIDClaim("sub"))

	// This is an actual Dex-encoded user ID
	dexEncodedID := "CiQ3YWFkOGMwNS0zMjg3LTQ3M2YtYjQyYS0zNjU1MDRiZjI1ZTcSBWxvY2Fs"

	claims := jwt.MapClaims{
		"sub":   dexEncodedID,
		"email": "dex@example.com",
		"name":  "Dex User",
	}

	token := &jwt.Token{Claims: claims}

	userAuth, err := extractor.ToUserAuth(token)
	require.NoError(t, err)

	// The extractor should pass through the encoded ID as-is
	// Decoding is done elsewhere (e.g., in the Dex provider)
	assert.Equal(t, dexEncodedID, userAuth.UserId)
	assert.Equal(t, "dex@example.com", userAuth.Email)
	assert.Equal(t, "Dex User", userAuth.Name)
}
