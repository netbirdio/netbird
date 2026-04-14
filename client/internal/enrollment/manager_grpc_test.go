package enrollment

// This file contains tests for the Manager methods that require a mocked gRPC
// client: EnsureCertificate (valid cert, expiring cert, no cert) and
// pollUntilApproved (approved status, context cancellation, rejected status).
// saveState failure path is also tested here.
//
// The mockEnrollmentClient below satisfies the enrollmentClient interface
// defined in manager.go without requiring a real gRPC connection.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/tpm"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// mockEnrollmentClient is a test double for the enrollmentClient interface.
type mockEnrollmentClient struct {
	enrollResp *proto.DeviceEnrollResponse
	enrollErr  error

	// statusResponses is consumed in order; when exhausted, statusErr is returned.
	statusResponses []*proto.DeviceEnrollResponse
	statusErr       error
	callCount       int

	// TPM attestation mocks.
	beginTPMResp *proto.BeginTPMAttestationResponse
	beginTPMErr  error
	completeResp *proto.AttestationResult
	completeErr  error

	// Apple SE attestation mock.
	attestSEResp *proto.AttestationResult
	attestSEErr  error
}

func (m *mockEnrollmentClient) EnrollDevice(_ string, _ string, _ *proto.AttestationProof) (*proto.DeviceEnrollResponse, error) {
	return m.enrollResp, m.enrollErr
}

func (m *mockEnrollmentClient) GetEnrollmentStatus(_ string) (*proto.DeviceEnrollResponse, error) {
	if m.callCount < len(m.statusResponses) {
		resp := m.statusResponses[m.callCount]
		m.callCount++
		return resp, nil
	}
	return nil, m.statusErr
}

func (m *mockEnrollmentClient) BeginTPMAttestation(_ context.Context, _ *proto.BeginTPMAttestationRequest) (*proto.BeginTPMAttestationResponse, error) {
	return m.beginTPMResp, m.beginTPMErr
}

func (m *mockEnrollmentClient) CompleteTPMAttestation(_ context.Context, _ *proto.CompleteTPMAttestationRequest) (*proto.AttestationResult, error) {
	return m.completeResp, m.completeErr
}

func (m *mockEnrollmentClient) AttestAppleSE(_ context.Context, _ *proto.AttestAppleSERequest) (*proto.AttestationResult, error) {
	return m.attestSEResp, m.attestSEErr
}

// seCapableMockProvider wraps MockProvider and adds CreateSEAttestation to
// simulate the Darwin SE provider in tests.
type seCapableMockProvider struct {
	*tpm.MockProvider
	seChain [][]byte
	seErr   error
}

func (p *seCapableMockProvider) CreateSEAttestation(_ context.Context, _ string) ([][]byte, error) {
	return p.seChain, p.seErr
}

// certPEMFor encodes a parsed certificate back to PEM.
func certPEMFor(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// newManager builds a Manager wired with the given mock client, a fresh temp
// dir for state, and a MockProvider with a generated key pre-loaded.
func newManagerWithMock(t *testing.T, mc *mockEnrollmentClient) (*Manager, *tpm.MockProvider) {
	t.Helper()
	provider := tpm.NewMockProvider()
	m := &Manager{
		tpmProvider: provider,
		grpcClient:  mc,
		stateFile:   filepath.Join(t.TempDir(), "enrollment.json"),
		wgPubKey:    "test-wg-pubkey",
	}
	return m, provider
}

// --- EnsureCertificate: valid cert ---

// TestEnsureCertificate_ValidCertNoEnrollment verifies that when a valid cert is
// already stored, EnsureCertificate returns it without calling the gRPC client.
func TestEnsureCertificate_ValidCertNoEnrollment(t *testing.T) {
	mc := &mockEnrollmentClient{
		enrollErr: errors.New("should not be called"),
	}
	m, provider := newManagerWithMock(t, mc)
	ctx := context.Background()

	// Pre-store a valid cert (expires far in the future).
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)
	validCert := newSelfSignedCert(t, time.Now().Add(30*24*time.Hour))
	require.NoError(t, provider.StoreCert(ctx, deviceKeyID, validCert))

	got, err := m.EnsureCertificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, validCert.SerialNumber, got.SerialNumber,
		"should return the already-stored valid cert without re-enrolling")
}

// --- EnsureCertificate: expiring cert triggers re-enrollment ---

// TestEnsureCertificate_ExpiringCertTriggersReEnrollment verifies that a cert
// expiring within the renewal threshold causes a new enrollment to be submitted.
func TestEnsureCertificate_ExpiringCertTriggersReEnrollment(t *testing.T) {
	ctx := context.Background()
	provider := tpm.NewMockProvider()
	// Force Mode A (no hardware attestation) so the test exercises the EnrollDevice path.
	provider.AttestationProofFunc = func(_ context.Context, _ string) (*tpm.AttestationProof, error) {
		return nil, tpm.ErrAttestationNotSupported
	}

	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	// Expiring in 6 days — below the 7-day renewal threshold.
	expiringCert := newSelfSignedCert(t, time.Now().Add(6*24*time.Hour))
	require.NoError(t, provider.StoreCert(ctx, deviceKeyID, expiringCert))

	// The approved response includes a fresh cert.
	freshCert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))

	mc := &mockEnrollmentClient{
		enrollResp: &proto.DeviceEnrollResponse{
			EnrollmentId:  "enroll-123",
			Status:        types.EnrollmentStatusApproved,
			DeviceCertPem: certPEMFor(freshCert),
		},
	}

	m := &Manager{
		tpmProvider: provider,
		grpcClient:  mc,
		stateFile:   filepath.Join(t.TempDir(), "enrollment.json"),
		wgPubKey:    "test-wg-pubkey",
	}

	got, err := m.EnsureCertificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, freshCert.SerialNumber, got.SerialNumber,
		"expiring cert must trigger re-enrollment returning the fresh cert")
}

// --- EnsureCertificate: no cert, immediately approved ---

// TestEnsureCertificate_NoCertFirstEnrollment verifies the full enrollment flow
// when there is no existing certificate: GenerateKey → CSR → EnrollDevice →
// approved response → StoreCert.
func TestEnsureCertificate_NoCertFirstEnrollment(t *testing.T) {
	ctx := context.Background()

	freshCert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))

	mc := &mockEnrollmentClient{
		enrollResp: &proto.DeviceEnrollResponse{
			EnrollmentId:  "enroll-456",
			Status:        types.EnrollmentStatusApproved,
			DeviceCertPem: certPEMFor(freshCert),
		},
	}

	m, provider := newManagerWithMock(t, mc)
	// Force Mode A (no hardware attestation) so the test exercises the EnrollDevice path.
	provider.AttestationProofFunc = func(_ context.Context, _ string) (*tpm.AttestationProof, error) {
		return nil, tpm.ErrAttestationNotSupported
	}

	got, err := m.EnsureCertificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, freshCert.SerialNumber, got.SerialNumber)
}

// --- EnsureCertificate: resume pending from saved state ---

// TestEnsureCertificate_ResumesPendingEnrollment verifies that if there is an
// existing pending enrollment in state, we skip re-submission and poll.
func TestEnsureCertificate_ResumesPendingEnrollment(t *testing.T) {
	ctx := context.Background()

	freshCert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))

	mc := &mockEnrollmentClient{
		statusResponses: []*proto.DeviceEnrollResponse{
			{
				EnrollmentId:  "saved-enroll-id",
				Status:        types.EnrollmentStatusApproved,
				DeviceCertPem: certPEMFor(freshCert),
			},
		},
	}

	m, provider := newManagerWithMock(t, mc)

	// Pre-generate the key so storeCertFromPEM can store to it.
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	// Persist a pending state.
	require.NoError(t, m.saveState(&enrollmentState{
		EnrollmentID: "saved-enroll-id",
		Status:       types.EnrollmentStatusPending,
		WGPublicKey:  "test-wg-pubkey",
	}))

	got, err := m.EnsureCertificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, freshCert.SerialNumber, got.SerialNumber)
}

// --- pollUntilApproved ---

// TestPollUntilApproved_ApprovedOnFirstPoll verifies that when GetEnrollmentStatus
// returns "approved" immediately, the cert is stored and returned.
func TestPollUntilApproved_ApprovedOnFirstPoll(t *testing.T) {
	ctx := context.Background()

	freshCert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))

	mc := &mockEnrollmentClient{
		statusResponses: []*proto.DeviceEnrollResponse{
			{
				EnrollmentId:  "poll-id",
				Status:        types.EnrollmentStatusApproved,
				DeviceCertPem: certPEMFor(freshCert),
			},
		},
	}

	m, provider := newManagerWithMock(t, mc)
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	got, err := m.pollUntilApproved(ctx, "poll-id")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, freshCert.SerialNumber, got.SerialNumber)
}

// TestPollUntilApproved_ContextCancelled verifies that pollUntilApproved returns
// the context error when the context is cancelled before approval.
func TestPollUntilApproved_ContextCancelled(t *testing.T) {
	// The mock never returns an approved response, just keeps returning pending.
	mc := &mockEnrollmentClient{
		// statusErr causes every poll to fail, triggering backoff, but the context
		// will be cancelled first.
		statusErr: errors.New("server unavailable"),
	}

	m, _ := newManagerWithMock(t, mc)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately — the poll loop must respect context cancellation.
	cancel()

	_, err := m.pollUntilApproved(ctx, "any-id")
	assert.ErrorIs(t, err, context.Canceled,
		"pollUntilApproved must return context.Canceled when ctx is cancelled")
}

// TestPollUntilApproved_RejectedReturnsError verifies that a rejected enrollment
// causes pollUntilApproved to return a descriptive error.
func TestPollUntilApproved_RejectedReturnsError(t *testing.T) {
	mc := &mockEnrollmentClient{
		statusResponses: []*proto.DeviceEnrollResponse{
			{
				EnrollmentId: "rejected-id",
				Status:       types.EnrollmentStatusRejected,
				Reason:       "device not trusted",
			},
		},
	}

	m, _ := newManagerWithMock(t, mc)
	ctx := context.Background()

	_, err := m.pollUntilApproved(ctx, "rejected-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rejected",
		"error must mention that the enrollment was rejected")
	assert.Contains(t, err.Error(), "device not trusted")
}

// --- saveState ---

// TestSaveState_AtomicWriteFailure verifies that saveState returns an error when
// the parent directory cannot be created (e.g. path is a file, not a directory).
func TestSaveState_AtomicWriteFailure(t *testing.T) {
	// Create a regular file where the directory would be.
	tmpDir := t.TempDir()
	blocker := filepath.Join(tmpDir, "enrollment-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("not-a-dir"), 0600))

	m := &Manager{
		// stateFile inside the "blocker" path — MkdirAll will fail.
		stateFile: filepath.Join(blocker, "enrollment.json"),
	}

	err := m.saveState(&enrollmentState{
		EnrollmentID: "test",
		Status:       types.EnrollmentStatusPending,
	})
	require.Error(t, err, "saveState must return error when directory creation fails")
}

// TestSaveState_Roundtrip verifies the happy-path save → load cycle (regression guard).
func TestSaveState_Roundtrip(t *testing.T) {
	m := &Manager{stateFile: filepath.Join(t.TempDir(), "enrollment.json")}
	state := &enrollmentState{
		EnrollmentID: "roundtrip-id",
		Status:       types.EnrollmentStatusApproved,
		WGPublicKey:  "wg-key",
	}
	require.NoError(t, m.saveState(state))
	loaded, err := m.loadState()
	require.NoError(t, err)
	assert.Equal(t, state.EnrollmentID, loaded.EnrollmentID)
	assert.Equal(t, state.Status, loaded.Status)
	assert.Equal(t, state.WGPublicKey, loaded.WGPublicKey)
}

// --- buildCSR ---

// TestBuildCSR_WithECKey verifies buildCSR with a freshly generated ECDSA signer.
// This exercises the 80% → 100% coverage gap on the happy path.
func TestBuildCSR_WithECKey(t *testing.T) {
	provider := tpm.NewMockProvider()
	signer, err := provider.GenerateKey(context.Background(), "build-csr-key")
	require.NoError(t, err)

	csrPEM, err := buildCSR(signer, "my-wg-pubkey")
	require.NoError(t, err)
	require.NotEmpty(t, csrPEM)

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)
}

// ─── TPM attestation enrollment ───────────────────────────────────────────────

// TestEnrollWithTPMAttestation_HappyPath verifies the two-round TPM credential
// activation flow: BeginTPMAttestation → ActivateCredential → CompleteTPMAttestation.
func TestEnrollWithTPMAttestation_HappyPath(t *testing.T) {
	ctx := context.Background()

	freshCert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))

	mc := &mockEnrollmentClient{
		beginTPMResp: &proto.BeginTPMAttestationResponse{
			SessionId:      "tpm-session-abc",
			CredentialBlob: []byte("fake-blob"),
		},
		completeResp: &proto.AttestationResult{
			EnrollmentId:  "tpm-enroll-1",
			Status:        "approved",
			DeviceCertPem: certPEMFor(freshCert),
		},
	}

	provider := tpm.NewMockProvider()
	provider.ActivateCredentialFunc = func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("decrypted-secret"), nil
	}
	provider.AttestationProofFunc = func(_ context.Context, _ string) (*tpm.AttestationProof, error) {
		return &tpm.AttestationProof{
			EKCert:   []byte("fake-ek-cert-der"),
			AKPublic: []byte("fake-ak-pub-der"),
		}, nil
	}
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	m := &Manager{
		tpmProvider: provider,
		grpcClient:  mc,
		stateFile:   filepath.Join(t.TempDir(), "enrollment.json"),
		wgPubKey:    "test-wg-pubkey",
	}

	cert, err := m.enrollWithTPMAttestation(ctx)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, freshCert.SerialNumber, cert.SerialNumber)
}

// TestEnrollWithTPMAttestation_ActivateCredentialFails verifies that a failure in
// TPM2_ActivateCredential propagates as an error.
func TestEnrollWithTPMAttestation_ActivateCredentialFails(t *testing.T) {
	ctx := context.Background()

	mc := &mockEnrollmentClient{
		beginTPMResp: &proto.BeginTPMAttestationResponse{
			SessionId:      "sess-fail",
			CredentialBlob: []byte("blob"),
		},
	}

	provider := tpm.NewMockProvider()
	provider.ActivateCredentialFunc = func(_ context.Context, _ []byte) ([]byte, error) {
		return nil, errors.New("tpm: hardware error")
	}
	provider.AttestationProofFunc = func(_ context.Context, _ string) (*tpm.AttestationProof, error) {
		return &tpm.AttestationProof{EKCert: []byte("ek"), AKPublic: []byte("ak")}, nil
	}
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	m := &Manager{tpmProvider: provider, grpcClient: mc, stateFile: t.TempDir() + "/s.json", wgPubKey: "wg"}
	_, err = m.enrollWithTPMAttestation(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ActivateCredential")
}

// ─── Apple SE attestation enrollment ──────────────────────────────────────────

// TestEnrollWithAppleSEAttestation_HappyPath verifies the single-round SE attestation
// flow: CreateSEAttestation → AttestAppleSE → cert stored.
func TestEnrollWithAppleSEAttestation_HappyPath(t *testing.T) {
	ctx := context.Background()

	freshCert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))

	mc := &mockEnrollmentClient{
		attestSEResp: &proto.AttestationResult{
			EnrollmentId:  "se-enroll-1",
			Status:        "approved",
			DeviceCertPem: certPEMFor(freshCert),
		},
	}

	fakeDER := freshCert.Raw // use cert DER as a stand-in attestation leaf
	baseProv := tpm.NewMockProvider()
	_, err := baseProv.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	provider := &seCapableMockProvider{
		MockProvider: baseProv,
		seChain:      [][]byte{fakeDER},
	}

	m := &Manager{
		tpmProvider: provider,
		grpcClient:  mc,
		stateFile:   filepath.Join(t.TempDir(), "enrollment.json"),
		wgPubKey:    "test-wg-pubkey",
	}

	cert, err := m.enrollWithAppleSEAttestation(ctx)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, freshCert.SerialNumber, cert.SerialNumber)
}

// TestEnrollWithAppleSEAttestation_NotSupportedOnNonDarwin verifies that
// enrollWithAppleSEAttestation returns an error when the provider does not
// implement CreateSEAttestation (non-Darwin platforms).
func TestEnrollWithAppleSEAttestation_NotSupportedOnNonDarwin(t *testing.T) {
	ctx := context.Background()
	mc := &mockEnrollmentClient{}
	provider := tpm.NewMockProvider()

	m := &Manager{tpmProvider: provider, grpcClient: mc, stateFile: t.TempDir() + "/s.json", wgPubKey: "wg"}
	_, err := m.enrollWithAppleSEAttestation(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SE attestation not supported")
}
