package deviceinventory_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/deviceinventory"
	"github.com/netbirdio/netbird/management/server/secretenc"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// newJamfMockServer creates a mock Jamf Pro server that handles both the
// OAuth token endpoint and the computers-inventory endpoint.
func newJamfMockServer(t *testing.T, wantToken string, computerIDs []string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/oauth/token":
			require.Equal(t, http.MethodPost, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": wantToken,
				"expires_in":   3600,
			})

		case "/api/v1/computers-inventory":
			require.Equal(t, "Bearer "+wantToken, r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")

			results := make([]map[string]string, 0, len(computerIDs))
			for _, id := range computerIDs {
				results = append(results, map[string]string{"id": id})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"results": results,
			})

		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

// newJamfInventoryWithMock builds a JamfInventory pointing at the mock server.
func newJamfInventoryWithMock(t *testing.T, srv *httptest.Server) *deviceinventory.JamfInventory {
	t.Helper()

	cfg, err := json.Marshal(map[string]interface{}{
		"url":           srv.URL,
		"client_id":     "test-client",
		"client_secret": "test-secret",
	})
	require.NoError(t, err)

	inv, err := deviceinventory.NewJamfInventory(string(cfg))
	require.NoError(t, err)
	return inv
}

// ─── IsRegistered ─────────────────────────────────────────────────────────────

func TestJamfInventory_IsRegistered_ReturnsTrueWhenComputerFound(t *testing.T) {
	srv := newJamfMockServer(t, "jamf-access-token", []string{"computer-1", "computer-2"})
	defer srv.Close()

	inv := newJamfInventoryWithMock(t, srv)

	ok, err := inv.IsRegistered(context.Background(), "123456789")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestJamfInventory_IsRegistered_ReturnsFalseWhenNoComputersMatch(t *testing.T) {
	srv := newJamfMockServer(t, "tok", nil) // empty results list
	defer srv.Close()

	inv := newJamfInventoryWithMock(t, srv)

	ok, err := inv.IsRegistered(context.Background(), "999999999")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestJamfInventory_IsRegistered_RejectsNonDecimalSerial(t *testing.T) {
	srv := newJamfMockServer(t, "tok", nil)
	defer srv.Close()

	inv := newJamfInventoryWithMock(t, srv)

	cases := []struct {
		serial string
		desc   string
	}{
		{"abc123", "hex chars"},
		{"123 456", "space"},
		{"12-34", "dash"},
		{"12.34", "dot"},
		{"0x1F", "hex prefix"},
		{"'; DROP TABLE--", "SQL injection attempt"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ok, err := inv.IsRegistered(context.Background(), tc.serial)
			require.Error(t, err, "expected error for serial %q", tc.serial)
			assert.False(t, ok)
			assert.Contains(t, err.Error(), "decimal digits")
		})
	}
}

func TestJamfInventory_IsRegistered_ReturnsErrorOnAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok",
				"expires_in":   3600,
			})
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	inv := newJamfInventoryWithMock(t, srv)

	ok, err := inv.IsRegistered(context.Background(), "12345")
	require.Error(t, err)
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "500")
}

func TestJamfInventory_IsRegistered_ReturnsErrorWhenTokenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token endpoint returns error.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	inv := newJamfInventoryWithMock(t, srv)

	ok, err := inv.IsRegistered(context.Background(), "12345")
	require.Error(t, err)
	assert.False(t, ok)
}

// ─── getAccessToken caching ───────────────────────────────────────────────────

func TestJamfInventory_GetAccessToken_CachesTokenUntilExpiry(t *testing.T) {
	var tokenCallCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/oauth/token":
			atomic.AddInt32(&tokenCallCount, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "cached-jamf-token",
				"expires_in":   3600,
			})
		case "/api/v1/computers-inventory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	inv := newJamfInventoryWithMock(t, srv)
	ctx := context.Background()

	// Make three consecutive calls — token should only be fetched once.
	_, err := inv.IsRegistered(ctx, "111")
	require.NoError(t, err)
	_, err = inv.IsRegistered(ctx, "222")
	require.NoError(t, err)
	_, err = inv.IsRegistered(ctx, "333")
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&tokenCallCount),
		"token should be fetched only once when not expired")
}

// ─── Config validation ────────────────────────────────────────────────────────

func TestNewJamfInventory_MissingURL_ReturnsError(t *testing.T) {
	_, err := deviceinventory.NewJamfInventory(`{"client_id":"c","client_secret":"s"}`)
	require.Error(t, err)
}

func TestNewJamfInventory_MissingClientID_ReturnsError(t *testing.T) {
	_, err := deviceinventory.NewJamfInventory(`{"url":"https://company.jamfcloud.com","client_secret":"s"}`)
	require.Error(t, err)
}

func TestNewJamfInventory_MissingClientSecret_ReturnsError(t *testing.T) {
	_, err := deviceinventory.NewJamfInventory(`{"url":"https://company.jamfcloud.com","client_id":"c"}`)
	require.Error(t, err)
}

func TestNewJamfInventory_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := deviceinventory.NewJamfInventory("not-json{")
	require.Error(t, err)
}

func TestNewJamfInventory_ValidConfig_Succeeds(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"url":           "https://company.jamfcloud.com",
		"client_id":     "jamf-client",
		"client_secret": "jamf-secret",
	})
	inv, err := deviceinventory.NewJamfInventory(string(cfg))
	require.NoError(t, err)
	assert.NotNil(t, inv)
}

func TestNewJamfInventory_CustomTimeout_Applied(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"url":            "https://company.jamfcloud.com",
		"client_id":      "jamf-client",
		"client_secret":  "jamf-secret",
		"timeout_seconds": 5,
	})
	inv, err := deviceinventory.NewJamfInventory(string(cfg))
	require.NoError(t, err)
	assert.NotNil(t, inv)
}

// ─── Token URL path construction ──────────────────────────────────────────────

// ─── EncryptSecrets / DecryptSecrets ─────────────────────────────────────────

func TestJamfConfig_EncryptDecryptSecrets_RoundTrip(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := deviceinventory.JamfConfig{
		URL:          "https://company.jamfcloud.com",
		ClientID:     "jamf-client",
		ClientSecret: "jamf-secret-789",
	}
	original := cfg.ClientSecret

	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.True(t, strings.HasPrefix(cfg.ClientSecret, "enc:"), "encrypted secret must have enc: prefix")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, original, cfg.ClientSecret)
}

func TestJamfConfig_EncryptDecryptSecrets_EmptySecret_NoOp(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := deviceinventory.JamfConfig{}

	require.NoError(t, cfg.EncryptSecrets(kp))
	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Empty(t, cfg.ClientSecret)
}

func TestJamfConfig_DecryptSecrets_PlaintextBackwardCompat(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := deviceinventory.JamfConfig{ClientSecret: "jamf-api-client-secret-plaintext"}

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "jamf-api-client-secret-plaintext", cfg.ClientSecret,
		"plaintext secret without enc: prefix must be left unchanged")
}

func TestJamfConfig_EncryptSecrets_DoubleEncryptGuard(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := deviceinventory.JamfConfig{ClientSecret: "jamf-secret-789"}

	require.NoError(t, cfg.EncryptSecrets(kp))
	encrypted := cfg.ClientSecret

	require.NoError(t, cfg.EncryptSecrets(kp))
	assert.Equal(t, encrypted, cfg.ClientSecret, "double encrypt must be a no-op")
}

func TestJamfConfig_DecryptSecrets_Base64PlaintextBackwardCompat(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	cfg := deviceinventory.JamfConfig{ClientSecret: "amFtZi1zZWNyZXQ="}  // base64("jamf-secret")

	require.NoError(t, cfg.DecryptSecrets(kp))
	assert.Equal(t, "amFtZi1zZWNyZXQ=", cfg.ClientSecret,
		"base64-looking plaintext without enc: prefix must be left unchanged")
}

// ─── Token URL path construction ──────────────────────────────────────────────

func TestJamfInventory_TokenURL_TrimsTrailingSlash(t *testing.T) {
	tokenCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth/token" {
			tokenCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok",
				"expires_in":   3600,
			})
			return
		}
		// Computers endpoint — return empty.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
	}))
	defer srv.Close()

	// Provide URL with trailing slash — implementation trims it.
	cfg, err := json.Marshal(map[string]interface{}{
		"url":           srv.URL + "/",
		"client_id":     "c",
		"client_secret": "s",
	})
	require.NoError(t, err)

	inv, err := deviceinventory.NewJamfInventory(string(cfg))
	require.NoError(t, err)

	_, err = inv.IsRegistered(context.Background(), "12345")
	require.NoError(t, err)
	assert.True(t, tokenCalled, "token endpoint must be called at /api/oauth/token")
}
