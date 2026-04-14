package device_auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

// ─── GET /device-auth/ca/config ───────────────────────────────────────────────

// TestGetCAConfig_Builtin verifies that when no CAConfig is stored, the endpoint
// returns ca_type "builtin" with no CA-specific sub-object.
func TestGetCAConfig_Builtin(t *testing.T) {
	const (
		accountID = "acc-builtin"
		userID    = "user-builtin"
	)

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:   types.DeviceAuthCATypeBuiltin,
			CAConfig: "",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/ca/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp caConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, types.DeviceAuthCATypeBuiltin, resp.CAType)
	assert.Nil(t, resp.Vault)
	assert.Nil(t, resp.Smallstep)
	assert.Nil(t, resp.SCEP)
}

// TestGetCAConfig_Vault verifies that a stored Vault config is returned with the
// token redacted (empty string) and has_token set to true.
func TestGetCAConfig_Vault(t *testing.T) {
	const (
		accountID = "acc-vault"
		userID    = "user-vault"
	)

	caConfigJSON := `{"address":"https://vault.example.com:8200","token":"s.secrettoken","mount":"pki","role":"netbird","namespace":"","timeout_seconds":30}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:   types.DeviceAuthCATypeVault,
			CAConfig: caConfigJSON,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/ca/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp caConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, types.DeviceAuthCATypeVault, resp.CAType)
	require.NotNil(t, resp.Vault)
	assert.Equal(t, "https://vault.example.com:8200", resp.Vault.Address)
	assert.Equal(t, "", resp.Vault.Token, "token must be redacted")
	assert.True(t, resp.Vault.HasToken, "has_token must be true when token is non-empty")
	assert.Equal(t, "pki", resp.Vault.Mount)
	assert.Equal(t, "netbird", resp.Vault.Role)
	assert.Equal(t, 30, resp.Vault.TimeoutSeconds)
	assert.Nil(t, resp.Smallstep)
	assert.Nil(t, resp.SCEP)
}

// TestGetCAConfig_Smallstep verifies that a stored Smallstep config is returned
// with the provisioner_token redacted and has_provisioner_token set to true.
func TestGetCAConfig_Smallstep(t *testing.T) {
	const (
		accountID = "acc-smallstep"
		userID    = "user-smallstep"
	)

	caConfigJSON := `{"url":"https://ca.example.com:9000","provisioner_token":"eyJhbGciOiJFUzI1NiJ9.secret","fingerprint":"abc123","timeout_seconds":15}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:   types.DeviceAuthCATypeSmallstep,
			CAConfig: caConfigJSON,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/ca/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp caConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, types.DeviceAuthCATypeSmallstep, resp.CAType)
	require.NotNil(t, resp.Smallstep)
	assert.Equal(t, "https://ca.example.com:9000", resp.Smallstep.URL)
	assert.Equal(t, "", resp.Smallstep.ProvisionerToken, "provisioner_token must be redacted")
	assert.True(t, resp.Smallstep.HasProvisionerToken, "has_provisioner_token must be true when token is non-empty")
	assert.Equal(t, "abc123", resp.Smallstep.Fingerprint)
	assert.Equal(t, 15, resp.Smallstep.TimeoutSeconds)
	assert.Nil(t, resp.Vault)
	assert.Nil(t, resp.SCEP)
}

// TestGetCAConfig_SCEP verifies that a stored SCEP config is returned with the
// challenge redacted and has_challenge set to true.
func TestGetCAConfig_SCEP(t *testing.T) {
	const (
		accountID = "acc-scep"
		userID    = "user-scep"
	)

	caConfigJSON := `{"url":"http://scep.example.com/scep","challenge":"mysecretpassword","timeout_seconds":20}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:   types.DeviceAuthCATypeSCEP,
			CAConfig: caConfigJSON,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device-auth/ca/config", nil)
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp caConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, types.DeviceAuthCATypeSCEP, resp.CAType)
	require.NotNil(t, resp.SCEP)
	assert.Equal(t, "http://scep.example.com/scep", resp.SCEP.URL)
	assert.Equal(t, "", resp.SCEP.Challenge, "challenge must be redacted")
	assert.True(t, resp.SCEP.HasChallenge, "has_challenge must be true when challenge is non-empty")
	assert.Equal(t, 20, resp.SCEP.TimeoutSeconds)
	assert.Nil(t, resp.Vault)
	assert.Nil(t, resp.Smallstep)
}

// ─── PUT /device-auth/ca/config ───────────────────────────────────────────────

// TestPutCAConfig_Vault_UpdatesNonCredentialFields verifies that sending a new
// address with an empty token preserves the existing token.
func TestPutCAConfig_Vault_UpdatesNonCredentialFields(t *testing.T) {
	const (
		accountID = "acc-vault-put"
		userID    = "user-vault-put"
	)

	existingCAConfigJSON := `{"address":"https://old.vault.com:8200","token":"existingtoken","mount":"pki","role":"netbird","namespace":"","timeout_seconds":30}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:   types.DeviceAuthCATypeVault,
			CAConfig: existingCAConfigJSON,
		},
	}

	// Send update with new address and empty token — token must be preserved.
	putBody := caConfigRequest{
		CAType: types.DeviceAuthCATypeVault,
		Vault: &vaultCfgReq{
			Address:        "https://new.vault.com:8200",
			Token:          "", // empty — preserve existing
			Mount:          "pki",
			Role:           "netbird",
			TimeoutSeconds: 30,
		},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/device-auth/ca/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp caConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, types.DeviceAuthCATypeVault, resp.CAType)
	require.NotNil(t, resp.Vault)
	assert.Equal(t, "https://new.vault.com:8200", resp.Vault.Address, "address should be updated")
	assert.Equal(t, "", resp.Vault.Token, "token must be redacted in response")
	assert.True(t, resp.Vault.HasToken, "has_token must be true because existing token was preserved")

	// Verify that the stored CAConfig actually contains the preserved token.
	saved := st.accountSettings[accountID]
	require.NotNil(t, saved.DeviceAuth)
	var savedCfg struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal([]byte(saved.DeviceAuth.CAConfig), &savedCfg))
	assert.Equal(t, "existingtoken", savedCfg.Token, "stored token must be preserved")
}

// TestPutCAConfig_Vault_UpdatesToken verifies that sending a non-empty token
// replaces the existing token in the stored config.
func TestPutCAConfig_Vault_UpdatesToken(t *testing.T) {
	const (
		accountID = "acc-vault-token"
		userID    = "user-vault-token"
	)

	existingCAConfigJSON := `{"address":"https://vault.example.com:8200","token":"oldtoken","mount":"pki","role":"netbird","namespace":"","timeout_seconds":30}`

	st := newMockStore()
	st.users[userID] = adminUser(userID, accountID)
	st.accountSettings[accountID] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{
			CAType:   types.DeviceAuthCATypeVault,
			CAConfig: existingCAConfigJSON,
		},
	}

	putBody := caConfigRequest{
		CAType: types.DeviceAuthCATypeVault,
		Vault: &vaultCfgReq{
			Address:        "https://vault.example.com:8200",
			Token:          "newtoken",
			Mount:          "pki",
			Role:           "netbird",
			TimeoutSeconds: 30,
		},
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/device-auth/ca/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth(accountID, userID))
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp caConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Vault.HasToken, "has_token must be true for the new token")

	// Verify the stored token was actually updated.
	saved := st.accountSettings[accountID]
	require.NotNil(t, saved.DeviceAuth)
	var savedCfg struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal([]byte(saved.DeviceAuth.CAConfig), &savedCfg))
	assert.Equal(t, "newtoken", savedCfg.Token, "stored token must be updated to new value")
}

// TestPutCAConfig_RequiresAdmin verifies that requests without valid admin auth
// are rejected with a 403/401 response.
func TestPutCAConfig_RequiresAdmin(t *testing.T) {
	st := newMockStore()

	putBody := caConfigRequest{
		CAType: types.DeviceAuthCATypeBuiltin,
	}
	body, err := json.Marshal(putBody)
	require.NoError(t, err)

	// No auth injected — requireAdmin should fail.
	req := httptest.NewRequest(http.MethodPut, "/device-auth/ca/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	makeRouter(st, nil).ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code, "expected non-200 when no auth is provided")
}

// TestGetCAConfig_RequiresAdmin verifies that GET requests with a user not
// present in the store are rejected (requireAdmin returns not ok).
func TestGetCAConfig_RequiresAdmin(t *testing.T) {
	st := newMockStore()
	// No user added — requireAdmin will fail because user is not in store.
	router := makeRouter(st, nil)

	req := httptest.NewRequest(http.MethodGet, "/device-auth/ca/config", nil)
	// withAuth injects auth but user is not in store → requireAdmin returns not ok.
	req = withAuth(req, adminAuth("acc1", "user1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be non-200 (not found user or permission denied).
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestGetCAConfig_NilDeviceAuth verifies that when DeviceAuth is nil in account
// settings, the endpoint returns ca_type "builtin" with a 200 status.
func TestGetCAConfig_NilDeviceAuth(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	// accountSettings has nil DeviceAuth.
	st.accountSettings["acc1"] = &types.Settings{DeviceAuth: nil}

	router := makeRouter(st, nil)
	req := httptest.NewRequest(http.MethodGet, "/device-auth/ca/config", nil)
	req = withAuth(req, adminAuth("acc1", "user1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "builtin", resp["ca_type"])
}

// TestPutCAConfig_Smallstep_PreservesToken verifies that sending an empty
// provisioner_token in the request preserves the existing stored token.
func TestPutCAConfig_Smallstep_PreservesToken(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	stepCfg := `{"url":"https://ca.example.com","provisioner_token":"secret-tok","fingerprint":"sha256:abc","timeout_seconds":30}`
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "smallstep", CAConfig: stepCfg},
	}

	router := makeRouter(st, nil)
	body := `{"ca_type":"smallstep","smallstep":{"url":"https://ca.example.com","provisioner_token":"","fingerprint":"sha256:abc","timeout_seconds":30}}`
	req := httptest.NewRequest(http.MethodPut, "/device-auth/ca/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// Verify stored settings preserve token.
	saved := st.accountSettings["acc1"]
	var savedCfg struct {
		ProvisionerToken string `json:"provisioner_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(saved.DeviceAuth.CAConfig), &savedCfg))
	assert.Equal(t, "secret-tok", savedCfg.ProvisionerToken)
}

// TestPutCAConfig_InvalidCAType verifies that PUT with an unrecognised ca_type
// returns 400 Bad Request without modifying the stored settings.
func TestPutCAConfig_InvalidCAType(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "builtin"},
	}

	router := makeRouter(st, nil)
	body := `{"ca_type":"bogus"}`
	req := httptest.NewRequest(http.MethodPut, "/device-auth/ca/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Stored settings must be unchanged.
	saved := st.accountSettings["acc1"]
	assert.Equal(t, "builtin", saved.DeviceAuth.CAType)
}

// TestPutCAConfig_MismatchedSubObject verifies that PUT with ca_type "vault" but
// a smallstep sub-object returns 400 Bad Request.
func TestPutCAConfig_MismatchedSubObject(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "builtin"},
	}

	router := makeRouter(st, nil)
	body := `{"ca_type":"vault","smallstep":{"url":"https://ca.example.com","fingerprint":"abc","timeout_seconds":10}}`
	req := httptest.NewRequest(http.MethodPut, "/device-auth/ca/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPutCAConfig_SCEP_PreservesChallenge verifies that sending an empty
// challenge in the request preserves the existing stored challenge.
func TestPutCAConfig_SCEP_PreservesChallenge(t *testing.T) {
	st := newMockStore()
	st.users["user1"] = adminUser("user1", "acc1")
	scepCfg := `{"url":"https://scep.example.com/scep","challenge":"my-challenge","timeout_seconds":30}`
	st.accountSettings["acc1"] = &types.Settings{
		DeviceAuth: &types.DeviceAuthSettings{CAType: "scep", CAConfig: scepCfg},
	}

	router := makeRouter(st, nil)
	body := `{"ca_type":"scep","scep":{"url":"https://scep.example.com/scep","challenge":"","timeout_seconds":30}}`
	req := httptest.NewRequest(http.MethodPut, "/device-auth/ca/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAuth(req, adminAuth("acc1", "user1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	saved := st.accountSettings["acc1"]
	var savedCfg struct {
		Challenge string `json:"challenge"`
	}
	require.NoError(t, json.Unmarshal([]byte(saved.DeviceAuth.CAConfig), &savedCfg))
	assert.Equal(t, "my-challenge", savedCfg.Challenge)
}
