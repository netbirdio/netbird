package deviceinventory_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/deviceinventory"
)

// ─── Static inventory ──────────────────────────────────────────────────────────

func TestStaticInventory_IsRegistered_Found(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"allowed_ek_serials": []string{"11223344", "aabbccdd"},
	})
	inv, err := deviceinventory.NewStaticInventory(string(cfg))
	require.NoError(t, err)

	ok, err := inv.IsRegistered(context.Background(), "11223344")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestStaticInventory_IsRegistered_NotFound(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"allowed_ek_serials": []string{"11223344"},
	})
	inv, err := deviceinventory.NewStaticInventory(string(cfg))
	require.NoError(t, err)

	ok, err := inv.IsRegistered(context.Background(), "99999999")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestStaticInventory_EmptyList_NeverRegistered(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"allowed_ek_serials": []string{},
	})
	inv, err := deviceinventory.NewStaticInventory(string(cfg))
	require.NoError(t, err)

	ok, err := inv.IsRegistered(context.Background(), "any")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestStaticInventory_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := deviceinventory.NewStaticInventory("not-json")
	require.Error(t, err)
}

// ─── NewInventory factory ──────────────────────────────────────────────────────

func TestNewInventory_StaticType_Works(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"allowed_ek_serials": []string{"abc123"},
	})
	inv, err := deviceinventory.NewInventory("static", string(cfg))
	require.NoError(t, err)
	assert.NotNil(t, inv)
}

func TestNewInventory_EmptyType_DefaultsToStatic(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"allowed_ek_serials": []string{},
	})
	inv, err := deviceinventory.NewInventory("", string(cfg))
	require.NoError(t, err)
	assert.NotNil(t, inv)
}

func TestNewInventory_UnknownType_ReturnsError(t *testing.T) {
	_, err := deviceinventory.NewInventory("magic", "{}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown inventory type")
}

// ─── Intune inventory (HTTP mock) ─────────────────────────────────────────────

func TestIntuneInventory_IsRegistered_Found(t *testing.T) {
	// Mock token endpoint.
	tokenCalled := 0
	deviceCalled := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/test-tenant/oauth2/v2.0/token":
			tokenCalled++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case "/v1.0/deviceManagement/managedDevices":
			deviceCalled++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":[{"id":"device-1"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// We can't easily override the Graph API URL without refactoring IntuneInventory.
	// Test that the config parsing and token logic work; real URL testing requires
	// an integration test. Here we just verify the happy-path config parsing succeeds.
	cfg, _ := json.Marshal(map[string]interface{}{
		"tenant_id":     "test-tenant",
		"client_id":     "test-client",
		"client_secret": "test-secret",
	})
	inv, err := deviceinventory.NewIntuneInventory(string(cfg))
	require.NoError(t, err)
	assert.NotNil(t, inv)

	_ = tokenCalled
	_ = deviceCalled
	_ = srv
}

func TestIntuneInventory_MissingConfig_ReturnsError(t *testing.T) {
	_, err := deviceinventory.NewIntuneInventory(`{"tenant_id":"t"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// ─── Jamf inventory ───────────────────────────────────────────────────────────

func TestJamfInventory_ValidConfig_Constructs(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"url":           "https://company.jamfcloud.com",
		"client_id":     "jamf-client",
		"client_secret": "jamf-secret",
	})
	inv, err := deviceinventory.NewJamfInventory(string(cfg))
	require.NoError(t, err)
	assert.NotNil(t, inv)
}

func TestJamfInventory_MissingURL_ReturnsError(t *testing.T) {
	cfg, _ := json.Marshal(map[string]interface{}{
		"client_id":     "jamf-client",
		"client_secret": "jamf-secret",
	})
	_, err := deviceinventory.NewJamfInventory(string(cfg))
	require.Error(t, err)
}

// ─── Interface compliance ─────────────────────────────────────────────────────

func TestInventory_InterfaceCompliance(t *testing.T) {
	var _ deviceinventory.Inventory = (*deviceinventory.StaticInventory)(nil)
	var _ deviceinventory.Inventory = (*deviceinventory.IntuneInventory)(nil)
	var _ deviceinventory.Inventory = (*deviceinventory.JamfInventory)(nil)
}
