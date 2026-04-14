package device_auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

// ─── GET /device-auth/inventory/config ────────────────────────────────────────

// TestGetInventoryConfig_Empty verifies that when no InventoryConfig is set, the
// endpoint returns three disabled sources with empty defaults.
func TestGetInventoryConfig_Empty(t *testing.T) {
	const (
		accountID = "acc-inv-empty"
		userID    = "user-inv-empty"
	)

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: "",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/inventory/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Static)
	assert.False(t, resp.Static.Enabled)
	assert.Empty(t, resp.Static.Peers)
	assert.Empty(t, resp.Static.Serials)
	require.NotNil(t, resp.Intune)
	assert.False(t, resp.Intune.Enabled)
	require.NotNil(t, resp.Jamf)
	assert.False(t, resp.Jamf.Enabled)
}

// TestGetInventoryConfig_Static verifies that a stored static inventory config
// is returned with the peer list and serial count.
func TestGetInventoryConfig_Static(t *testing.T) {
	const (
		accountID = "acc-inv-static"
		userID    = "user-inv-static"
	)

	invConfigJSON := `{"static":{"enabled":true,"peers":["peer-aaa","peer-bbb"],"serials":["SN001","SN002","SN003"]}}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: invConfigJSON,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/inventory/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Static)
	assert.True(t, resp.Static.Enabled)
	assert.Equal(t, []string{"peer-aaa", "peer-bbb"}, resp.Static.Peers)
	assert.Equal(t, []string{"SN001", "SN002", "SN003"}, resp.Static.Serials)
	require.NotNil(t, resp.Intune)
	assert.False(t, resp.Intune.Enabled)
	require.NotNil(t, resp.Jamf)
	assert.False(t, resp.Jamf.Enabled)
}

// TestGetInventoryConfig_Intune verifies that a stored Intune config is returned
// with client_secret redacted and has_client_secret=true.
func TestGetInventoryConfig_Intune(t *testing.T) {
	const (
		accountID = "acc-inv-intune"
		userID    = "user-inv-intune"
	)

	invConfigJSON := `{"intune":{"enabled":true,"tenant_id":"tenant-123","client_id":"client-456","client_secret":"super-secret","require_compliance":true}}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: invConfigJSON,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/inventory/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Intune)
	assert.True(t, resp.Intune.Enabled)
	assert.Equal(t, "tenant-123", resp.Intune.TenantID)
	assert.Equal(t, "client-456", resp.Intune.ClientID)
	assert.Equal(t, "", resp.Intune.ClientSecret, "client_secret must be redacted")
	assert.True(t, resp.Intune.HasClientSecret, "has_client_secret must be true when secret is stored")
	assert.True(t, resp.Intune.RequireCompliance)
	require.NotNil(t, resp.Static)
	assert.False(t, resp.Static.Enabled)
	require.NotNil(t, resp.Jamf)
	assert.False(t, resp.Jamf.Enabled)
}

// TestGetInventoryConfig_Jamf verifies that a stored Jamf config is returned
// with client_secret redacted and has_client_secret=true.
func TestGetInventoryConfig_Jamf(t *testing.T) {
	const (
		accountID = "acc-inv-jamf"
		userID    = "user-inv-jamf"
	)

	invConfigJSON := `{"jamf":{"enabled":true,"jamf_url":"https://jamf.example.com","client_id":"api-client","client_secret":"s3cr3t","require_management":true}}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: invConfigJSON,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/inventory/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Jamf)
	assert.True(t, resp.Jamf.Enabled)
	assert.Equal(t, "https://jamf.example.com", resp.Jamf.JamfURL)
	assert.Equal(t, "api-client", resp.Jamf.ClientID)
	assert.Equal(t, "", resp.Jamf.ClientSecret, "client_secret must be redacted")
	assert.True(t, resp.Jamf.HasClientSecret, "has_client_secret must be true when secret is stored")
	assert.True(t, resp.Jamf.RequireManagement)
	require.NotNil(t, resp.Static)
	assert.False(t, resp.Static.Enabled)
	require.NotNil(t, resp.Intune)
	assert.False(t, resp.Intune.Enabled)
}

// TestGetInventoryConfig_MultiSource verifies that multiple simultaneous sources
// are all returned correctly.
func TestGetInventoryConfig_MultiSource(t *testing.T) {
	const (
		accountID = "acc-inv-multi"
		userID    = "user-inv-multi"
	)

	invConfigJSON := `{
		"static":{"enabled":true,"peers":["peer-aaa"],"serials":["SN001"]},
		"intune":{"enabled":true,"tenant_id":"tenant-123","client_id":"client-456","client_secret":"secret","require_compliance":false},
		"jamf":{"enabled":false,"jamf_url":"https://jamf.example.com","client_id":"","client_secret":"","require_management":false}
	}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: invConfigJSON,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/inventory/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Static)
	assert.True(t, resp.Static.Enabled)
	assert.Equal(t, []string{"SN001"}, resp.Static.Serials)
	require.NotNil(t, resp.Intune)
	assert.True(t, resp.Intune.Enabled)
	assert.True(t, resp.Intune.HasClientSecret)
	require.NotNil(t, resp.Jamf)
	assert.False(t, resp.Jamf.Enabled)
}

// ─── PUT /device-auth/inventory/config ────────────────────────────────────────

// TestPutInventoryConfig_Static_UpdatesPeers verifies that sending a new peer list
// updates the stored static inventory config.
func TestPutInventoryConfig_Static_UpdatesPeers(t *testing.T) {
	const (
		accountID = "acc-inv-static-put"
		userID    = "user-inv-static-put"
	)

	existingConfigJSON := `{"static":{"enabled":true,"peers":["old-peer"],"serials":[]}}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: existingConfigJSON,
		},
	}

	putBody := inventoryConfigRequest{
		Static: &staticInvReq{
			Enabled: true,
			Peers:   []string{"peer-new-1", "peer-new-2"},
		},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/device-auth/inventory/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Static)
	assert.True(t, resp.Static.Enabled)
	assert.Equal(t, []string{"peer-new-1", "peer-new-2"}, resp.Static.Peers)

	// Verify stored settings have been updated.
	saved := st.accountSettings[accountID]
	require.NotNil(t, saved.DeviceAuth)
	var savedCfg multiStoredConfig
	require.NoError(t, json.Unmarshal([]byte(saved.DeviceAuth.InventoryConfig), &savedCfg))
	require.NotNil(t, savedCfg.Static)
	assert.Equal(t, []string{"peer-new-1", "peer-new-2"}, savedCfg.Static.Peers)
}

// TestPutInventoryConfig_Intune_PreservesSecret verifies that sending an empty
// client_secret in the request preserves the existing stored secret.
func TestPutInventoryConfig_Intune_PreservesSecret(t *testing.T) {
	const (
		accountID = "acc-inv-intune-put"
		userID    = "user-inv-intune-put"
	)

	existingConfigJSON := `{"intune":{"enabled":true,"tenant_id":"tenant-123","client_id":"client-456","client_secret":"existing-secret","require_compliance":false}}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: existingConfigJSON,
		},
	}

	putBody := inventoryConfigRequest{
		Intune: &intuneConfigReq{
			Enabled:           true,
			TenantID:          "tenant-123",
			ClientID:          "client-456",
			ClientSecret:      "", // empty — preserve existing
			RequireCompliance: true,
		},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/device-auth/inventory/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Intune)
	assert.True(t, resp.Intune.Enabled)
	assert.Equal(t, "", resp.Intune.ClientSecret, "client_secret must be redacted in response")
	assert.True(t, resp.Intune.HasClientSecret, "has_client_secret must be true because existing secret was preserved")
	assert.True(t, resp.Intune.RequireCompliance, "require_compliance should be updated to true")

	// Verify the stored config actually contains the preserved secret.
	saved := st.accountSettings[accountID]
	require.NotNil(t, saved.DeviceAuth)
	var savedCfg multiStoredConfig
	require.NoError(t, json.Unmarshal([]byte(saved.DeviceAuth.InventoryConfig), &savedCfg))
	require.NotNil(t, savedCfg.Intune)
	assert.Equal(t, "existing-secret", savedCfg.Intune.ClientSecret, "stored secret must be preserved")
}

// TestPutInventoryConfig_Jamf_PreservesSecret verifies that sending an empty
// client_secret in the request preserves the existing stored secret.
func TestPutInventoryConfig_Jamf_PreservesSecret(t *testing.T) {
	const (
		accountID = "acc-inv-jamf-put"
		userID    = "user-inv-jamf-put"
	)

	existingConfigJSON := `{"jamf":{"enabled":true,"jamf_url":"https://jamf.example.com","client_id":"api-client","client_secret":"existing-pass","require_management":false}}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			InventoryConfig: existingConfigJSON,
		},
	}

	putBody := inventoryConfigRequest{
		Jamf: &jamfConfigReq{
			Enabled:           true,
			JamfURL:           "https://jamf.example.com",
			ClientID:          "api-client",
			ClientSecret:      "", // empty — preserve existing
			RequireManagement: true,
		},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/device-auth/inventory/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Jamf)
	assert.True(t, resp.Jamf.Enabled)
	assert.Equal(t, "", resp.Jamf.ClientSecret, "client_secret must be redacted in response")
	assert.True(t, resp.Jamf.HasClientSecret, "has_client_secret must be true because existing secret was preserved")
	assert.True(t, resp.Jamf.RequireManagement, "require_management should be updated to true")

	// Verify the stored config actually contains the preserved secret.
	saved := st.accountSettings[accountID]
	require.NotNil(t, saved.DeviceAuth)
	var savedCfg multiStoredConfig
	require.NoError(t, json.Unmarshal([]byte(saved.DeviceAuth.InventoryConfig), &savedCfg))
	require.NotNil(t, savedCfg.Jamf)
	assert.Equal(t, "existing-pass", savedCfg.Jamf.ClientSecret, "stored secret must be preserved")
}

// TestPutInventoryConfig_MultiSource verifies that multiple sources can be
// enabled simultaneously and each is stored independently.
func TestPutInventoryConfig_MultiSource(t *testing.T) {
	const (
		accountID = "acc-inv-multi-put"
		userID    = "user-inv-multi-put"
	)

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{},
	}

	putBody := inventoryConfigRequest{
		Static: &staticInvReq{Enabled: true, Peers: []string{"peer-x"}},
		Intune: &intuneConfigReq{
			Enabled:      true,
			TenantID:     "t1",
			ClientID:     "c1",
			ClientSecret: "secret1",
		},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/device-auth/inventory/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Static)
	assert.True(t, resp.Static.Enabled)
	assert.Equal(t, []string{"peer-x"}, resp.Static.Peers)
	require.NotNil(t, resp.Intune)
	assert.True(t, resp.Intune.Enabled)
	assert.Equal(t, "t1", resp.Intune.TenantID)
	assert.True(t, resp.Intune.HasClientSecret)
	require.NotNil(t, resp.Jamf)
	assert.False(t, resp.Jamf.Enabled)
}

// TestPutInventoryConfig_RequiresAdmin verifies that requests without valid admin
// auth are rejected with a non-200 response.
func TestPutInventoryConfig_RequiresAdmin(t *testing.T) {
	st := newMockStore()

	putBody := inventoryConfigRequest{
		Static: &staticInvReq{Enabled: true},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	// No auth injected — requireAdmin should fail.
	req := httptest.NewRequest(http.MethodPut, "/device-auth/inventory/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code, "expected non-200 when no auth is provided")
}

// TestPutInventoryConfig_SerialRoundtrip verifies that serials sent in a PUT are
// stored and returned verbatim by a subsequent GET, and that omitting the serials
// field in a second PUT preserves the existing serials.
func TestPutInventoryConfig_SerialRoundtrip(t *testing.T) {
	const (
		accountID = "acc-inv-serial-rt"
		userID    = "user-inv-serial-rt"
	)

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{},
	}

	serials := []string{"ABC-123", "DEF-456"}
	putBody := inventoryConfigRequest{
		Static: &staticInvReq{
			Enabled: true,
			Peers:   []string{},
			Serials: &serials,
		},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	putReq := httptest.NewRequest(http.MethodPut, "/device-auth/inventory/config", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq = withAuth(putReq, adminAuth(accountID, userID))
	putW := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(putW, putReq)
	require.Equal(t, http.StatusOK, putW.Code)

	getReq := httptest.NewRequest(http.MethodGet, "/device-auth/inventory/config", nil)
	getReq = withAuth(getReq, adminAuth(accountID, userID))
	getW := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(getW, getReq)
	require.Equal(t, http.StatusOK, getW.Code)

	var resp inventoryConfigResponse
	require.NoError(t, json.Unmarshal(getW.Body.Bytes(), &resp))
	require.NotNil(t, resp.Static)
	assert.Equal(t, []string{"ABC-123", "DEF-456"}, resp.Static.Serials)

	// A second PUT without a serials field must preserve the existing serials.
	putBody2 := inventoryConfigRequest{
		Static: &staticInvReq{
			Enabled: true,
			Peers:   []string{"peer-x"},
			// Serials intentionally omitted (nil pointer) — existing must be preserved.
		},
	}
	body2, err := json.Marshal(putBody2)
	require.NoError(t, err)

	putReq2 := httptest.NewRequest(http.MethodPut, "/device-auth/inventory/config", bytes.NewReader(body2))
	putReq2.Header.Set("Content-Type", "application/json")
	putReq2 = withAuth(putReq2, adminAuth(accountID, userID))
	putW2 := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(putW2, putReq2)
	require.Equal(t, http.StatusOK, putW2.Code)

	var resp2 inventoryConfigResponse
	require.NoError(t, json.Unmarshal(putW2.Body.Bytes(), &resp2))
	require.NotNil(t, resp2.Static)
	assert.Equal(t, []string{"ABC-123", "DEF-456"}, resp2.Static.Serials, "serials must be preserved when not sent in PUT")
	assert.Equal(t, []string{"peer-x"}, resp2.Static.Peers)
}
