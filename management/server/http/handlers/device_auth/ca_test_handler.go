package device_auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// caTestStepStatus describes the outcome of one step in the CA test cycle.
type caTestStepStatus string

const (
	caTestStepOK      caTestStepStatus = "ok"
	caTestStepError   caTestStepStatus = "error"
	caTestStepSkipped caTestStepStatus = "skipped"

	// caTestStepTimeout is the per-step deadline for each CA operation.
	// This prevents a slow or unresponsive CA backend from blocking the HTTP handler
	// indefinitely when the request context has a longer (or no) deadline.
	caTestStepTimeout = 15 * time.Second
)

// caTestStep is the result of one step in the CA test lifecycle.
type caTestStep struct {
	Name      string           `json:"name"`
	Status    caTestStepStatus `json:"status"`
	Detail    string           `json:"detail"`
	FixHint   string           `json:"fix_hint,omitempty"`
	ElapsedMs int64            `json:"elapsed_ms"`
}

// caTestResponse is returned by POST /device-auth/ca/test.
type caTestResponse struct {
	Success bool         `json:"success"`
	Steps   []caTestStep `json:"steps"`
}

// postCATest runs a 5-step certificate lifecycle test against the configured CA
// without persisting any changes to the store. The request body has the same
// shape as PUT /device-auth/ca/config. Credential fields left empty in the
// request are filled from the account's stored settings.
func (h *handler) postCATest(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	var req caConfigRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	// Load stored settings so we can merge in request credentials.
	accountSettings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// Clone stored DeviceAuthSettings to avoid mutating the stored value.
	stored := accountSettings.DeviceAuth
	if stored == nil {
		stored = &types.DeviceAuthSettings{}
	}
	settingsCopy := stored.Copy()

	// Merge request fields (preserves existing credentials when request leaves them empty).
	if err := applyCAConfigRequest(settingsCopy, req); err != nil {
		util.WriteErrorResponse("invalid CA config: "+err.Error(), http.StatusBadRequest, w)
		return
	}

	resp := h.runCATestCycle(r.Context(), settingsCopy, userAuth.AccountId)
	util.WriteJSONObject(r.Context(), w, resp)
}

// runCATestCycle executes the 5-step certificate lifecycle and returns the results.
//
// Safety: the test certificate issued in step 2 is immediately revoked in step 4 and is
// never persisted to the store. For the builtin CA backend, SignCSR operates entirely
// in-memory and does not call store.SaveDeviceCertificate; for external CA backends
// (Vault, Smallstep, SCEP) the certificate is issued through the external API and then
// revoked via RevokeCert in the same test cycle so no long-lived test certificate remains.
func (h *handler) runCATestCycle(ctx context.Context, settings *types.DeviceAuthSettings, accountID string) *caTestResponse {
	resp := &caTestResponse{Steps: make([]caTestStep, 0, 5)}

	addStep := func(name string, status caTestStepStatus, detail, hint string, elapsed time.Duration) {
		resp.Steps = append(resp.Steps, caTestStep{
			Name:      name,
			Status:    status,
			Detail:    detail,
			FixHint:   hint,
			ElapsedMs: elapsed.Milliseconds(),
		})
	}

	skipRemaining := func(names ...string) {
		for _, n := range names {
			addStep(n, caTestStepSkipped, "", "", 0)
		}
	}

	// Step 1: Generate an ephemeral ECDSA P-256 CSR.
	start := time.Now()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		addStep("generate_csr", caTestStepError, "Failed to generate ECDSA key: "+err.Error(), "Internal error", time.Since(start))
		skipRemaining("sign_certificate", "verify_certificate", "revoke_certificate", "verify_crl")
		return resp
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "netbird-ca-test"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		addStep("generate_csr", caTestStepError, "Failed to create CSR: "+err.Error(), "Internal error", time.Since(start))
		skipRemaining("sign_certificate", "verify_certificate", "revoke_certificate", "verify_crl")
		return resp
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		addStep("generate_csr", caTestStepError, "Failed to parse CSR: "+err.Error(), "Internal error", time.Since(start))
		skipRemaining("sign_certificate", "verify_certificate", "revoke_certificate", "verify_crl")
		return resp
	}
	addStep("generate_csr", caTestStepOK, "ECDSA P-256 CSR generated", "", time.Since(start))

	// Initialise the CA backend.
	ca, err := h.caFactory(ctx, settings, accountID, h.store, h.managementURL)
	if err != nil {
		addStep("sign_certificate", caTestStepError, "Failed to initialise CA: "+err.Error(), "Check CA type and configuration", 0)
		skipRemaining("verify_certificate", "revoke_certificate", "verify_crl")
		return resp
	}

	// Step 2: Sign the CSR (validity of 1 day is sufficient for the test).
	if ctx.Err() != nil {
		skipRemaining("sign_certificate", "verify_certificate", "revoke_certificate", "verify_crl")
		return resp
	}
	start = time.Now()
	signCtx, signCancel := context.WithTimeout(ctx, caTestStepTimeout)
	defer signCancel()
	cert, err := ca.SignCSR(signCtx, csr, "netbird-ca-test", 1)
	if err != nil {
		hint := caErrorHint(settings.CAType, err)
		addStep("sign_certificate", caTestStepError, err.Error(), hint, time.Since(start))
		skipRemaining("verify_certificate", "revoke_certificate", "verify_crl")
		return resp
	}
	serial := cert.SerialNumber.String()
	addStep("sign_certificate", caTestStepOK, "Signed · Serial: "+serial, "", time.Since(start))

	// Step 3: Verify the issued certificate's validity window.
	if ctx.Err() != nil {
		skipRemaining("verify_certificate", "revoke_certificate", "verify_crl")
		return resp
	}
	start = time.Now()
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		addStep("verify_certificate", caTestStepError, "Certificate validity period is invalid", "Check CA clock synchronisation", time.Since(start))
		skipRemaining("revoke_certificate", "verify_crl")
		return resp
	}
	addStep("verify_certificate", caTestStepOK, "Valid · Serial: "+serial, "", time.Since(start))

	// Step 4: Revoke the certificate.
	if ctx.Err() != nil {
		skipRemaining("revoke_certificate", "verify_crl")
		return resp
	}
	start = time.Now()
	revokeCtx, revokeCancel := context.WithTimeout(ctx, caTestStepTimeout)
	defer revokeCancel()
	if err := ca.RevokeCert(revokeCtx, serial); err != nil {
		hint := caErrorHint(settings.CAType, err)
		addStep("revoke_certificate", caTestStepError, err.Error(), hint, time.Since(start))
		addStep("verify_crl", caTestStepSkipped, "", "", 0)
		return resp
	}
	addStep("revoke_certificate", caTestStepOK, "Serial "+serial+" revoked", "", time.Since(start))

	// Step 5: Generate a CRL and confirm it was produced.
	if ctx.Err() != nil {
		skipRemaining("verify_crl")
		return resp
	}
	start = time.Now()
	crlCtx, crlCancel := context.WithTimeout(ctx, caTestStepTimeout)
	defer crlCancel()
	crlBytes, err := ca.GenerateCRL(crlCtx)
	if err != nil {
		addStep("verify_crl", caTestStepError, err.Error(), "Check CA CRL generation permissions", time.Since(start))
		return resp
	}
	detail := "CRL generated"
	if len(crlBytes) > 0 {
		detail = "CRL generated successfully"
	}
	addStep("verify_crl", caTestStepOK, detail, "", time.Since(start))

	resp.Success = true
	return resp
}

// caErrorHint returns a human-readable remediation hint for common CA errors.
func caErrorHint(caType string, err error) string {
	msg := err.Error()
	switch caType {
	case "vault":
		if strings.Contains(msg, "permission denied") || strings.Contains(msg, "403") {
			return "Check Vault token permissions: vault token capabilities <mount>/sign/<role>"
		}
		if strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") {
			return "Check Vault address is reachable from the management server"
		}
	case "smallstep":
		if strings.Contains(msg, "unauthorized") {
			return "Check the Provisioner Token has not expired and matches the provisioner"
		}
	case "scep":
		if strings.Contains(msg, "challenge") {
			return "Check the SCEP challenge password matches the server configuration"
		}
	}
	return ""
}
