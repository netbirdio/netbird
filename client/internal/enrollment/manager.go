// Package enrollment manages the device certificate enrollment lifecycle.
// The Manager drives the TPM key generation → CSR submission → polling flow.
package enrollment

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/tpm"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// enrollmentClient is the subset of the gRPC management client used by Manager.
// It exists to allow test doubles without pulling in the full gRPC stack.
type enrollmentClient interface {
	EnrollDevice(csrPEM, systemInfo string, attestationProof *proto.AttestationProof) (*proto.DeviceEnrollResponse, error)
	GetEnrollmentStatus(enrollmentID string) (*proto.DeviceEnrollResponse, error)
	BeginTPMAttestation(ctx context.Context, req *proto.BeginTPMAttestationRequest) (*proto.BeginTPMAttestationResponse, error)
	CompleteTPMAttestation(ctx context.Context, req *proto.CompleteTPMAttestationRequest) (*proto.AttestationResult, error)
	AttestAppleSE(ctx context.Context, req *proto.AttestAppleSERequest) (*proto.AttestationResult, error)
}

// seAttestationProvider is implemented by the macOS darwinProvider.
// It is not part of the Provider interface because it is Darwin-specific.
type seAttestationProvider interface {
	CreateSEAttestation(ctx context.Context, keyID string) ([][]byte, error)
}

// ErrNotEnrolled is returned by BuildTLSCertificate when no device certificate
// has been issued yet (the device has not completed the enrollment flow).
var ErrNotEnrolled = errors.New("device certificate not enrolled")

const (
	// deviceKeyID is the well-known TPM key label used for device certificates.
	deviceKeyID = "device-key"

	// renewalThreshold is how far in advance of expiry we trigger renewal.
	renewalThreshold = 7 * 24 * time.Hour

	// renewalInterval is how often the renewal loop wakes up to check certificate validity.
	renewalInterval = 6 * time.Hour

	// pollInitial is the first poll interval after submitting a CSR.
	pollInitial = 5 * time.Second
	// pollMax is the maximum back-off interval between polls.
	pollMax = 5 * time.Minute
)

// enrollmentState is the on-disk state persisted across restarts.
type enrollmentState struct {
	EnrollmentID string `json:"enrollment_id"`
	Status       string `json:"status"`
	WGPublicKey  string `json:"wg_public_key"`
}

// Manager handles the full device certificate enrollment lifecycle.
type Manager struct {
	mu          sync.Mutex
	tpmProvider tpm.Provider
	grpcClient  enrollmentClient
	stateFile   string
	wgPubKey    string
}

// NewManager creates a Manager. stateDir is the directory where the on-disk
// enrollment state file is written. wgPubKey is the peer's WireGuard public key.
func NewManager(tpmProvider tpm.Provider, grpcClient enrollmentClient, stateDir, wgPubKey string) *Manager {
	return &Manager{
		tpmProvider: tpmProvider,
		grpcClient:  grpcClient,
		stateFile:   filepath.Join(stateDir, "enrollment.json"),
		wgPubKey:    wgPubKey,
	}
}

// EnsureCertificate returns a valid device certificate, enrolling or renewing as needed.
//
//  1. If a valid (not revoked, >7d remaining) cert is found in the TPM store → return it.
//  2. If a cert is expiring in <7d → start renewal (submit new CSR, pending old one aside).
//  3. If no cert → GenerateKey → CSR → EnrollDevice RPC → poll GetEnrollmentStatus.
//  4. On approval → StoreCert → return cert.
func (m *Manager) EnsureCertificate(ctx context.Context) (*x509.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Check for a valid existing certificate.
	existing, err := m.tpmProvider.LoadCert(ctx, deviceKeyID)
	if err == nil && certIsValid(existing) {
		log.Debug("enrollment: found valid device certificate, skipping enrollment")
		return existing, nil
	}

	// 2. Load persisted enrollment state (if any).
	// File-not-found is expected on first run; parse errors are logged since they
	// indicate corruption — the manager will re-enroll from scratch in that case.
	state, loadStateErr := m.loadState()
	if loadStateErr != nil && !errors.Is(loadStateErr, os.ErrNotExist) {
		log.Warnf("enrollment: load state: %v (will re-enroll from scratch)", loadStateErr)
	}

	// If we have a pending request, poll rather than re-submit.
	if state != nil && state.Status == types.EnrollmentStatusPending {
		log.Infof("enrollment: resuming polling for enrollment %s", state.EnrollmentID)
		cert, pollErr := m.pollUntilApproved(ctx, state.EnrollmentID)
		if pollErr != nil {
			return nil, pollErr
		}
		// Mark state as approved so subsequent restarts skip the poll loop.
		state.Status = types.EnrollmentStatusApproved
		if saveErr := m.saveState(state); saveErr != nil {
			log.Warnf("enrollment: update state to approved: %v", saveErr)
		}
		return cert, nil
	}

	// 3. Generate TPM key (required for all enrollment paths).
	if _, err = m.tpmProvider.GenerateKey(ctx, deviceKeyID); err != nil {
		return nil, fmt.Errorf("enrollment: generate TPM key: %w", err)
	}

	// 4. Dispatch to hardware attestation paths when available.
	//    Apple SE attestation takes priority on Darwin; TPM credential activation
	//    is used on Linux/Windows when attestation evidence is present.
	//    Fall back to the legacy EnrollDevice RPC (Mode A) when neither is available.
	if _, ok := m.tpmProvider.(seAttestationProvider); ok {
		log.Infof("enrollment: using Apple SE attestation for peer %s", m.wgPubKey)
		return m.enrollWithAppleSEAttestation(ctx)
	}

	ap, apErr := m.tpmProvider.AttestationProof(ctx, deviceKeyID)
	if apErr == nil && len(ap.EKCert) > 0 {
		log.Infof("enrollment: using TPM credential activation for peer %s", m.wgPubKey)
		return m.enrollWithTPMAttestation(ctx)
	}

	log.Infof("enrollment: submitting CSR via Mode A (no attestation) for peer %s", m.wgPubKey)

	// 5. Mode A: legacy EnrollDevice RPC — no hardware attestation available.
	signer, err := m.tpmProvider.LoadKey(ctx, deviceKeyID)
	if err != nil {
		return nil, fmt.Errorf("enrollment: load device key: %w", err)
	}

	csrPEM, err := buildCSR(signer, m.wgPubKey)
	if err != nil {
		return nil, fmt.Errorf("enrollment: build CSR: %w", err)
	}

	resp, err := m.grpcClient.EnrollDevice(csrPEM, m.buildSystemInfo(), nil)
	if err != nil {
		return nil, fmt.Errorf("enrollment: EnrollDevice RPC: %w", err)
	}

	newState := &enrollmentState{
		EnrollmentID: resp.EnrollmentId,
		Status:       resp.Status,
		WGPublicKey:  m.wgPubKey,
	}
	if saveErr := m.saveState(newState); saveErr != nil {
		log.Warnf("enrollment: save enrollment state: %v", saveErr)
	}

	if resp.Status == types.EnrollmentStatusApproved {
		return m.storeCertFromPEM(ctx, resp.DeviceCertPem)
	}

	// 6. Poll until approved.
	return m.pollUntilApproved(ctx, resp.EnrollmentId)
}

// StartRenewalLoop starts a background goroutine that ensures the device
// certificate stays valid. It wakes up every renewalInterval (6 h) and calls
// EnsureCertificate; when the certificate changes (new serial number, e.g. after
// renewal), onRenewal is called with the fresh certificate.
//
// onRenewal is NOT called on the first iteration — it is used only to seed the
// last-seen serial so subsequent renewals can be detected. This prevents a
// spurious mTLS reconnect every time the client starts.
//
// The loop runs until ctx is cancelled. Errors are logged but do not stop the loop.
func (m *Manager) StartRenewalLoop(ctx context.Context, onRenewal func(*x509.Certificate)) {
	go func() {
		// firstRun is true before we have recorded any serial from this session.
		// On firstRun we seed lastSerial but do NOT call onRenewal — the cert was
		// already known to the caller before the loop started.
		firstRun := true
		var lastSerial string
		for {
			cert, err := m.EnsureCertificate(ctx)
			if err != nil {
				log.Errorf("enrollment: renewal loop: EnsureCertificate error: %v", err)
			} else if cert != nil {
				newSerial := cert.SerialNumber.String()
				if newSerial != lastSerial {
					lastSerial = newSerial
					// On the very first successful check, seed lastSerial without
					// notifying — the caller already holds this cert. On all
					// subsequent changes (renewal, re-enrollment) notify.
					if !firstRun && onRenewal != nil {
						onRenewal(cert)
					}
				}
				firstRun = false
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter(renewalInterval)):
			}
		}
	}()
}

// BuildTLSCertificate loads the enrolled device certificate and TPM private key and
// assembles a tls.Certificate ready for use as a gRPC mTLS client credential.
// Returns (nil, ErrNotEnrolled) if no certificate has been enrolled yet.
func (m *Manager) BuildTLSCertificate(ctx context.Context) (*tls.Certificate, error) {
	cert, err := m.tpmProvider.LoadCert(ctx, deviceKeyID)
	if err != nil {
		if errors.Is(err, tpm.ErrKeyNotFound) {
			return nil, ErrNotEnrolled
		}
		return nil, fmt.Errorf("load device cert: %w", err)
	}
	if cert == nil {
		return nil, ErrNotEnrolled
	}
	signer, err := m.tpmProvider.LoadKey(ctx, deviceKeyID)
	if err != nil {
		if errors.Is(err, tpm.ErrKeyNotFound) {
			return nil, fmt.Errorf("device cert exists but TPM key is missing (TPM may have been reset): %w", err)
		}
		return nil, fmt.Errorf("load device key: %w", err)
	}
	return &tls.Certificate{
		PrivateKey:  signer,
		Certificate: [][]byte{cert.Raw},
		Leaf:        cert,
	}, nil
}

// enrollWithTPMAttestation performs the two-round TPM 2.0 credential activation
// enrollment: BeginTPMAttestation (server MakeCredential) →
// ActivateCredential (client TPM2_ActivateCredential) →
// CompleteTPMAttestation (server verifies secret and issues cert).
func (m *Manager) enrollWithTPMAttestation(ctx context.Context) (*x509.Certificate, error) {
	signer, err := m.tpmProvider.LoadKey(ctx, deviceKeyID)
	if err != nil {
		return nil, fmt.Errorf("enrollment: load device key for TPM attestation: %w", err)
	}

	csrPEM, err := buildCSR(signer, m.wgPubKey)
	if err != nil {
		return nil, fmt.Errorf("enrollment: build CSR for TPM attestation: %w", err)
	}

	ap, err := m.tpmProvider.AttestationProof(ctx, deviceKeyID)
	if err != nil {
		return nil, fmt.Errorf("enrollment: get attestation proof: %w", err)
	}

	// Encode EK cert (DER) and AK public key (PKIX DER) as PEM for the server.
	ekCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ap.EKCert}))
	akPubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ap.AKPublic}))

	beginResp, err := m.grpcClient.BeginTPMAttestation(ctx, &proto.BeginTPMAttestationRequest{
		AkPubPem:   akPubPEM,
		EkCertPem:  ekCertPEM,
		CsrPem:     csrPEM,
		SystemInfo: m.buildSystemInfo(),
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment: BeginTPMAttestation: %w", err)
	}

	activatedSecret, err := m.tpmProvider.ActivateCredential(ctx, beginResp.GetCredentialBlob())
	if err != nil {
		return nil, fmt.Errorf("enrollment: ActivateCredential: %w", err)
	}

	result, err := m.grpcClient.CompleteTPMAttestation(ctx, &proto.CompleteTPMAttestationRequest{
		SessionId:       beginResp.GetSessionId(),
		ActivatedSecret: activatedSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment: CompleteTPMAttestation: %w", err)
	}

	if result.GetStatus() == "approved" && result.GetDeviceCertPem() != "" {
		return m.storeCertFromPEM(ctx, result.GetDeviceCertPem())
	}
	eid := result.GetEnrollmentId()
	if eid == "" {
		return nil, fmt.Errorf("enrollment: server returned pending status without enrollment_id for TPM attestation")
	}
	return m.pollUntilApproved(ctx, eid)
}

// enrollWithAppleSEAttestation performs single-round Apple Secure Enclave
// attestation enrollment using SecKeyCreateAttestation and the AttestAppleSE RPC.
func (m *Manager) enrollWithAppleSEAttestation(ctx context.Context) (*x509.Certificate, error) {
	darwinProv, ok := m.tpmProvider.(seAttestationProvider)
	if !ok {
		return nil, fmt.Errorf("enrollment: SE attestation not supported on this platform")
	}

	signer, err := m.tpmProvider.LoadKey(ctx, deviceKeyID)
	if err != nil {
		return nil, fmt.Errorf("enrollment: load SE key for attestation: %w", err)
	}

	csrPEM, err := buildCSR(signer, m.wgPubKey)
	if err != nil {
		return nil, fmt.Errorf("enrollment: build CSR for SE attestation: %w", err)
	}

	chain, err := darwinProv.CreateSEAttestation(ctx, deviceKeyID)
	if err != nil {
		return nil, fmt.Errorf("enrollment: CreateSEAttestation: %w", err)
	}

	chainPEMs := make([]string, len(chain))
	for i, der := range chain {
		chainPEMs[i] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	result, err := m.grpcClient.AttestAppleSE(ctx, &proto.AttestAppleSERequest{
		CsrPem:          csrPEM,
		AttestationPems: chainPEMs,
		SystemInfo:      m.buildSystemInfo(),
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment: AttestAppleSE: %w", err)
	}

	if result.GetStatus() == "approved" && result.GetDeviceCertPem() != "" {
		return m.storeCertFromPEM(ctx, result.GetDeviceCertPem())
	}
	eid := result.GetEnrollmentId()
	if eid == "" {
		return nil, fmt.Errorf("enrollment: server returned pending status without enrollment_id for SE attestation")
	}
	return m.pollUntilApproved(ctx, eid)
}

// buildSystemInfo returns a JSON-encoded metadata blob with device identity fields.
func (m *Manager) buildSystemInfo() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Warnf("enrollment: get hostname: %v — using 'unknown'", err)
		hostname = "unknown"
	}
	info := map[string]string{
		"hostname":   hostname,
		"wg_pub_key": m.wgPubKey,
	}
	data, _ := json.Marshal(info)
	return string(data)
}

// pollUntilApproved polls GetEnrollmentStatus with exponential back-off until
// the enrollment is approved, rejected, or the context is cancelled.
func (m *Manager) pollUntilApproved(ctx context.Context, enrollmentID string) (*x509.Certificate, error) {
	interval := pollInitial
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(jitter(interval)):
		}

		resp, err := m.grpcClient.GetEnrollmentStatus(enrollmentID)
		if err != nil {
			log.Warnf("enrollment: GetEnrollmentStatus error (will retry): %v", err)
			interval = backoff(interval)
			continue
		}

		log.Debugf("enrollment: status=%s for %s", resp.Status, enrollmentID)

		switch resp.Status {
		case types.EnrollmentStatusApproved:
			if saveErr := m.saveState(&enrollmentState{
				EnrollmentID: enrollmentID,
				Status:       resp.Status,
				WGPublicKey:  m.wgPubKey,
			}); saveErr != nil {
				log.Warnf("enrollment: save approved state: %v", saveErr)
			}
			return m.storeCertFromPEM(ctx, resp.DeviceCertPem)

		case types.EnrollmentStatusRejected:
			return nil, fmt.Errorf("enrollment: request %s was rejected: %s", enrollmentID, resp.Reason)
		}

		// Still pending — back off and retry.
		interval = backoff(interval)
	}
}

// storeCertFromPEM parses the PEM certificate, stores it in the TPM, and returns it.
func (m *Manager) storeCertFromPEM(ctx context.Context, certPEM string) (*x509.Certificate, error) {
	if certPEM == "" {
		return nil, errors.New("enrollment: received empty certificate PEM")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("enrollment: failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("enrollment: parse certificate: %w", err)
	}

	if err := m.tpmProvider.StoreCert(ctx, deviceKeyID, cert); err != nil {
		return nil, fmt.Errorf("enrollment: store certificate: %w", err)
	}

	log.Infof("enrollment: device certificate stored (serial %s, expires %s)",
		cert.SerialNumber, cert.NotAfter.Format(time.RFC3339))

	return cert, nil
}

// loadState reads the on-disk enrollment state.
func (m *Manager) loadState() (*enrollmentState, error) {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		return nil, err
	}
	var state enrollmentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// saveState persists the enrollment state to disk.
func (m *Manager) saveState(state *enrollmentState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.stateFile), 0700); err != nil {
		return err
	}
	return os.WriteFile(m.stateFile, data, 0600)
}

// buildCSR generates a PKCS#10 CSR signed with the given crypto.Signer.
// CN is set to the WireGuard public key (the future certificate Common Name).
func buildCSR(signer crypto.Signer, cn string) (string, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// certIsValid reports whether the certificate is within its validity window
// and has more than renewalThreshold remaining.
func certIsValid(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	now := time.Now()
	return now.After(cert.NotBefore) &&
		now.Before(cert.NotAfter) &&
		cert.NotAfter.Sub(now) > renewalThreshold
}

// backoff doubles the interval up to pollMax.
func backoff(d time.Duration) time.Duration {
	d *= 2
	if d > pollMax {
		d = pollMax
	}
	return d
}

// jitter adds ±10% random jitter to avoid thundering-herd on the management server.
// The global math/rand source is auto-seeded since Go 1.20 and is safe for concurrent
// use; cryptographic quality is not required for poll back-off jitter.
func jitter(d time.Duration) time.Duration {
	delta := float64(d) * 0.1
	return d + time.Duration((mrand.Float64()*2-1)*delta)
}
