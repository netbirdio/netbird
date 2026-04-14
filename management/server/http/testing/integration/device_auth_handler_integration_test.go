//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	testDeviceAuthSQL = "../testdata/device_auth_integration.sql"
	testWGKey         = "5rvhvriKJZ3S9oxYToVj5TzDM9u9y8cxg7htIMWlYAg="
)

// buildCSRPEM generates a valid PKCS#10 CSR PEM for use in enrollment tests.
func buildTestCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-device"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// saveTestEnrollment inserts a pending enrollment request for testPeerId.
func saveTestEnrollment(t *testing.T, st store.Store) *types.EnrollmentRequest {
	t.Helper()
	req := types.NewEnrollmentRequest(
		testing_tools.TestAccountId,
		testing_tools.TestPeerId,
		testWGKey,
		buildTestCSRPEM(t),
		`{"SystemSerialNumber":"SN-TEST-001","OS":"linux"}`,
	)
	require.NoError(t, st.SaveEnrollmentRequest(context.Background(), store.LockingStrengthNone, req))
	return req
}

// saveTestDeviceCert inserts a device certificate record.
func saveTestDeviceCert(t *testing.T, st store.Store) *types.DeviceCertificate {
	t.Helper()
	now := time.Now().UTC()
	cert := types.NewDeviceCertificate(
		testing_tools.TestAccountId,
		testing_tools.TestPeerId,
		testWGKey,
		"123456789",
		"-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
		now,
		now.AddDate(1, 0, 0),
	)
	require.NoError(t, st.SaveDeviceCertificate(context.Background(), store.LockingStrengthNone, cert))
	return cert
}

// ─── Enrollment list ──────────────────────────────────────────────────────────

func Test_DeviceAuth_ListEnrollments_RBAC(t *testing.T) {
	cases := []struct {
		name   string
		userID string
		status int
	}{
		{"admin can list", testing_tools.TestAdminId, http.StatusOK},
		{"owner can list", testing_tools.TestOwnerId, http.StatusOK},
		{"cert_approver can list", testing_tools.TestCertApproverId, http.StatusOK},
		{"regular user cannot list", testing_tools.TestUserId, http.StatusForbidden},
		// otherUserId belongs to otherAccountId which is not in the test fixture → 401
		{"other account user cannot list", testing_tools.OtherUserId, http.StatusUnauthorized},
		{"invalid token cannot list", testing_tools.InvalidToken, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
			saveTestEnrollment(t, am.GetStore())

			req := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/enrollments", tc.userID)
			rec := httptest.NewRecorder()
			apiHandler.ServeHTTP(rec, req)

			assert.Equal(t, tc.status, rec.Code, "unexpected status for %s", tc.name)
			if tc.status == http.StatusOK {
				var result []map[string]interface{}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
				assert.Len(t, result, 1)
			}
		})
	}
}

// ─── Enrollment approve ───────────────────────────────────────────────────────

func Test_DeviceAuth_ApproveEnrollment_Flow(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	st := am.GetStore()
	enrollment := saveTestEnrollment(t, st)

	url := "/api/device-auth/enrollments/" + enrollment.ID + "/approve"
	req := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestAdminId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "approve failed: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "approved", resp["status"])
	assert.Equal(t, enrollment.ID, resp["id"])

	// Verify a device certificate was created in the store.
	certs, err := st.ListDeviceCertificates(context.Background(), store.LockingStrengthNone, testing_tools.TestAccountId)
	require.NoError(t, err)
	require.Len(t, certs, 1, "expected exactly one device cert after approval")
	assert.Equal(t, testWGKey, certs[0].WGPublicKey)
	assert.False(t, certs[0].Revoked)
}

func Test_DeviceAuth_ApproveEnrollment_CertApprover(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	enrollment := saveTestEnrollment(t, am.GetStore())

	url := "/api/device-auth/enrollments/" + enrollment.ID + "/approve"
	req := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestCertApproverId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "cert_approver should be able to approve: %s", rec.Body.String())
}

func Test_DeviceAuth_ApproveEnrollment_RegularUserForbidden(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	enrollment := saveTestEnrollment(t, am.GetStore())

	url := "/api/device-auth/enrollments/" + enrollment.ID + "/approve"
	req := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestUserId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func Test_DeviceAuth_ApproveEnrollment_AlreadyApproved(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	st := am.GetStore()
	enrollment := saveTestEnrollment(t, st)

	// Approve once.
	url := "/api/device-auth/enrollments/" + enrollment.ID + "/approve"
	req := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestAdminId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "first approval failed: %s", rec.Body.String())

	// Approve again — must fail with 422.
	rec2 := httptest.NewRecorder()
	req2 := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestAdminId)
	apiHandler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnprocessableEntity, rec2.Code)
}

// ─── Enrollment reject ────────────────────────────────────────────────────────

func Test_DeviceAuth_RejectEnrollment_Admin(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	enrollment := saveTestEnrollment(t, am.GetStore())

	body := bytes.NewBufferString(`{"reason":"not a corporate device"}`)
	url := "/api/device-auth/enrollments/" + enrollment.ID + "/reject"
	req := testing_tools.BuildRequest(t, body.Bytes(), http.MethodPost, url, testing_tools.TestAdminId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "reject failed: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "rejected", resp["status"])
	assert.Equal(t, "not a corporate device", resp["reason"])
}

func Test_DeviceAuth_RejectEnrollment_CertApprover(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	enrollment := saveTestEnrollment(t, am.GetStore())

	url := "/api/device-auth/enrollments/" + enrollment.ID + "/reject"
	req := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestCertApproverId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func Test_DeviceAuth_RejectEnrollment_AlreadyRejected(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	st := am.GetStore()
	enrollment := saveTestEnrollment(t, st)

	url := "/api/device-auth/enrollments/" + enrollment.ID + "/reject"
	req1 := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestAdminId)
	rec1 := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	// Second reject — must fail with 422.
	req2 := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestAdminId)
	rec2 := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnprocessableEntity, rec2.Code)
}

// ─── Device certificate list ──────────────────────────────────────────────────

func Test_DeviceAuth_ListDevices_RBAC(t *testing.T) {
	cases := []struct {
		name   string
		userID string
		status int
	}{
		{"admin can list", testing_tools.TestAdminId, http.StatusOK},
		{"owner can list", testing_tools.TestOwnerId, http.StatusOK},
		{"cert_approver can list", testing_tools.TestCertApproverId, http.StatusOK},
		{"regular user cannot list", testing_tools.TestUserId, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
			saveTestDeviceCert(t, am.GetStore())

			req := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/devices", tc.userID)
			rec := httptest.NewRecorder()
			apiHandler.ServeHTTP(rec, req)

			assert.Equal(t, tc.status, rec.Code)
			if tc.status == http.StatusOK {
				var result []map[string]interface{}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
				assert.Len(t, result, 1)
			}
		})
	}
}

// ─── Device revoke ────────────────────────────────────────────────────────────

func Test_DeviceAuth_RevokeDevice_Admin(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	cert := saveTestDeviceCert(t, am.GetStore())

	url := "/api/device-auth/devices/" + cert.ID + "/revoke"
	req := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestAdminId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "revoke failed: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["revoked"])
}

func Test_DeviceAuth_RevokeDevice_CertApproverForbidden(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	cert := saveTestDeviceCert(t, am.GetStore())

	url := "/api/device-auth/devices/" + cert.ID + "/revoke"
	req := testing_tools.BuildRequest(t, nil, http.MethodPost, url, testing_tools.TestCertApproverId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ─── Settings ─────────────────────────────────────────────────────────────────

func Test_DeviceAuth_GetSettings_AdminOnly(t *testing.T) {
	cases := []struct {
		name   string
		userID string
		status int
	}{
		{"admin can get", testing_tools.TestAdminId, http.StatusOK},
		{"owner can get", testing_tools.TestOwnerId, http.StatusOK},
		{"cert_approver cannot get settings", testing_tools.TestCertApproverId, http.StatusForbidden},
		{"regular user cannot get settings", testing_tools.TestUserId, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
			req := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/settings", tc.userID)
			rec := httptest.NewRecorder()
			apiHandler.ServeHTTP(rec, req)
			assert.Equal(t, tc.status, rec.Code)
		})
	}
}

func Test_DeviceAuth_GetSettings_Defaults(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	req := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/settings", testing_tools.TestAdminId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "disabled", resp["mode"])
	assert.Equal(t, "builtin", resp["ca_type"])
	assert.Equal(t, float64(365), resp["cert_validity_days"])
}

func Test_DeviceAuth_UpdateSettings_Persist(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)

	body := `{"mode":"cert-only","enrollment_mode":"manual","cert_validity_days":180,"require_inventory_check":true}`
	putReq := testing_tools.BuildRequest(t, []byte(body), http.MethodPut, "/api/device-auth/settings", testing_tools.TestAdminId)
	putRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(putRec, putReq)
	require.Equal(t, http.StatusOK, putRec.Code, "PUT settings failed: %s", putRec.Body.String())

	// Verify the PUT response.
	var putResp map[string]interface{}
	require.NoError(t, json.Unmarshal(putRec.Body.Bytes(), &putResp))
	assert.Equal(t, "cert-only", putResp["mode"])
	assert.Equal(t, "manual", putResp["enrollment_mode"])
	assert.Equal(t, float64(180), putResp["cert_validity_days"])
	assert.Equal(t, true, putResp["require_inventory_check"])

	// Verify GET returns the same persisted values.
	getReq := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/settings", testing_tools.TestAdminId)
	getRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code)

	var getResp map[string]interface{}
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &getResp))
	assert.Equal(t, "cert-only", getResp["mode"])
	assert.Equal(t, float64(180), getResp["cert_validity_days"])
	assert.Equal(t, true, getResp["require_inventory_check"])
}

func Test_DeviceAuth_UpdateSettings_InvalidMode(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)

	body := `{"mode":"unknown-mode"}`
	req := testing_tools.BuildRequest(t, []byte(body), http.MethodPut, "/api/device-auth/settings", testing_tools.TestAdminId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func Test_DeviceAuth_UpdateSettings_CertApproverForbidden(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)

	body := `{"mode":"optional"}`
	req := testing_tools.BuildRequest(t, []byte(body), http.MethodPut, "/api/device-auth/settings", testing_tools.TestCertApproverId)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func Test_DeviceAuth_UpdateSettings_RequireInventoryCheck(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)

	// Enable require_inventory_check.
	enableBody := `{"require_inventory_check":true}`
	req1 := testing_tools.BuildRequest(t, []byte(enableBody), http.MethodPut, "/api/device-auth/settings", testing_tools.TestAdminId)
	rec1 := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	var resp1 map[string]interface{}
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &resp1))
	assert.Equal(t, true, resp1["require_inventory_check"])

	// Disable require_inventory_check.
	disableBody := `{"require_inventory_check":false}`
	req2 := testing_tools.BuildRequest(t, []byte(disableBody), http.MethodPut, "/api/device-auth/settings", testing_tools.TestAdminId)
	rec2 := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)

	var resp2 map[string]interface{}
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &resp2))
	assert.Equal(t, false, resp2["require_inventory_check"])
}

// ─── Trusted CA management ────────────────────────────────────────────────────

func Test_DeviceAuth_ListTrustedCAs_AdminOnly(t *testing.T) {
	cases := []struct {
		name   string
		userID string
		status int
	}{
		{"admin can list", testing_tools.TestAdminId, http.StatusOK},
		{"owner can list", testing_tools.TestOwnerId, http.StatusOK},
		{"cert_approver cannot list trusted CAs", testing_tools.TestCertApproverId, http.StatusForbidden},
		{"regular user cannot list trusted CAs", testing_tools.TestUserId, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
			req := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/trusted-cas", tc.userID)
			rec := httptest.NewRecorder()
			apiHandler.ServeHTTP(rec, req)
			assert.Equal(t, tc.status, rec.Code)
		})
	}
}

// ─── CRL endpoint (no auth) ───────────────────────────────────────────────────

func Test_DeviceAuth_GetCRL_PublicEndpoint(t *testing.T) {
	// CRL is publicly accessible — no auth token required.
	// We seed a builtin CA with a known CRL token directly in the store.
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	st := am.GetStore()

	certPEM, keyPEM, err := devicepki.NewBuiltinCA(testing_tools.TestAccountId)
	require.NoError(t, err)
	crlToken := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 hex chars
	caRecord := types.NewBuiltinTrustedCA(testing_tools.TestAccountId, "test-ca", certPEM, keyPEM)
	caRecord.CRLToken = &crlToken
	require.NoError(t, st.SaveTrustedCA(context.Background(), store.LockingStrengthUpdate, caRecord))

	url := "/api/device-auth/crl/" + crlToken
	req := testing_tools.BuildRequest(t, nil, http.MethodGet, url, "")
	req.Header.Del("Authorization")

	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "CRL endpoint should be publicly accessible: %s", rec.Body.String())
	assert.Equal(t, "application/pkix-crl", rec.Header().Get("Content-Type"))
}

func Test_DeviceAuth_GetCRL_UnknownToken(t *testing.T) {
	// An unknown 64-hex token must return 404 to prevent account enumeration.
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)

	unknownToken := "0000000000000000000000000000000000000000000000000000000000000001"
	req := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/crl/"+unknownToken, "")
	req.Header.Del("Authorization")
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ─── End-to-end enrollment flow ───────────────────────────────────────────────

// Test_DeviceAuth_FullEnrollmentFlow verifies the complete path:
// create enrollment → admin approves → list devices shows new cert → revoke cert.
func Test_DeviceAuth_FullEnrollmentFlow(t *testing.T) {
	apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
	st := am.GetStore()
	enrollment := saveTestEnrollment(t, st)

	// Step 1: admin approves the enrollment.
	approveURL := "/api/device-auth/enrollments/" + enrollment.ID + "/approve"
	approveReq := testing_tools.BuildRequest(t, nil, http.MethodPost, approveURL, testing_tools.TestAdminId)
	approveRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(approveRec, approveReq)
	require.Equal(t, http.StatusOK, approveRec.Code, "approve failed: %s", approveRec.Body.String())

	// Step 2: verify the enrollment now shows as approved in list.
	listEnrollReq := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/enrollments", testing_tools.TestAdminId)
	listEnrollRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(listEnrollRec, listEnrollReq)
	require.Equal(t, http.StatusOK, listEnrollRec.Code)

	var enrollments []map[string]interface{}
	require.NoError(t, json.Unmarshal(listEnrollRec.Body.Bytes(), &enrollments))
	require.Len(t, enrollments, 1)
	assert.Equal(t, "approved", enrollments[0]["status"])

	// Step 3: list devices — the new cert must appear.
	listDevicesReq := testing_tools.BuildRequest(t, nil, http.MethodGet, "/api/device-auth/devices", testing_tools.TestAdminId)
	listDevicesRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(listDevicesRec, listDevicesReq)
	require.Equal(t, http.StatusOK, listDevicesRec.Code)

	var devices []map[string]interface{}
	require.NoError(t, json.Unmarshal(listDevicesRec.Body.Bytes(), &devices))
	require.Len(t, devices, 1)
	certID := devices[0]["id"].(string)
	assert.Equal(t, testWGKey, devices[0]["wg_public_key"])
	assert.Equal(t, false, devices[0]["revoked"])

	// Step 4: revoke the device cert.
	revokeURL := "/api/device-auth/devices/" + certID + "/revoke"
	revokeReq := testing_tools.BuildRequest(t, nil, http.MethodPost, revokeURL, testing_tools.TestAdminId)
	revokeRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(revokeRec, revokeReq)
	require.Equal(t, http.StatusOK, revokeRec.Code, "revoke failed: %s", revokeRec.Body.String())

	var revoked map[string]interface{}
	require.NoError(t, json.Unmarshal(revokeRec.Body.Bytes(), &revoked))
	assert.Equal(t, true, revoked["revoked"])
	assert.NotEmpty(t, revoked["revoked_at"])
}

// ─── CertApprover RBAC sweep ──────────────────────────────────────────────────

// Test_DeviceAuth_CertApprover_AdminEndpoints verifies cert_approver is blocked
// from all admin-only operations in one table-driven test.
func Test_DeviceAuth_CertApprover_AdminEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"get settings", http.MethodGet, "/api/device-auth/settings"},
		{"update settings", http.MethodPut, "/api/device-auth/settings"},
		{"list trusted CAs", http.MethodGet, "/api/device-auth/trusted-cas"},
		{"create trusted CA", http.MethodPost, "/api/device-auth/trusted-cas"},
		{"get CA config", http.MethodGet, "/api/device-auth/ca/config"},
		{"put CA config", http.MethodPut, "/api/device-auth/ca/config"},
		{"get inventory config", http.MethodGet, "/api/device-auth/inventory/config"},
		{"put inventory config", http.MethodPut, "/api/device-auth/inventory/config"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, testDeviceAuthSQL, nil, false)
			cert := saveTestDeviceCert(t, am.GetStore())

			path := tc.path
			if tc.name == "revoke device" {
				path = "/api/device-auth/devices/" + cert.ID + "/revoke"
			}

			req := testing_tools.BuildRequest(t, []byte(`{}`), tc.method, path, testing_tools.TestCertApproverId)
			rec := httptest.NewRecorder()
			apiHandler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code, "cert_approver should be blocked from %s %s (got %d)", tc.method, path, rec.Code)
		})
	}
}
