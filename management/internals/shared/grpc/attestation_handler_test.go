package grpc

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/devicepki/appleroots"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestBeginTPMAttestation_InvalidEKCert_ReturnsError(t *testing.T) {
	s := &Server{attestationSessions: NewAttestationSessionStore()}
	req := &proto.BeginTPMAttestationRequest{
		EkCertPem: "not-a-valid-cert",
		AkPubPem:  "also-invalid",
		CsrPem:    "csr",
	}
	_, err := s.BeginTPMAttestation(context.Background(), req)
	require.Error(t, err, "invalid EK cert must return error")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestBeginTPMAttestation_EmptyEKCert_ReturnsError(t *testing.T) {
	s := &Server{attestationSessions: NewAttestationSessionStore()}
	req := &proto.BeginTPMAttestationRequest{
		EkCertPem: "",
		AkPubPem:  "",
		CsrPem:    "csr",
	}
	_, err := s.BeginTPMAttestation(context.Background(), req)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestCompleteTPMAttestation_UnknownSession_ReturnsNotFound(t *testing.T) {
	s := &Server{attestationSessions: NewAttestationSessionStore()}
	req := &proto.CompleteTPMAttestationRequest{
		// Valid 64-char hex format but not stored in the session store.
		SessionId:       "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		ActivatedSecret: []byte("secret"),
	}
	_, err := s.CompleteTPMAttestation(context.Background(), req)
	require.Error(t, err, "unknown session must return error")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestCompleteTPMAttestation_WrongSecret_ReturnsPermissionDenied(t *testing.T) {
	const validSID = "1122334455667788990011223344556677889900112233445566778899001122"
	s := &Server{attestationSessions: NewAttestationSessionStore()}
	require.NoError(t, s.attestationSessions.Put(validSID, AttestationSession{
		ExpectedSecret: []byte("correct-secret"),
		ExpiresAt:      time.Now().Add(time.Minute),
	}))
	req := &proto.CompleteTPMAttestationRequest{
		SessionId:       validSID,
		ActivatedSecret: []byte("wrong-secret"),
	}
	_, err := s.CompleteTPMAttestation(context.Background(), req)
	require.Error(t, err, "wrong secret must return error")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestCompleteTPMAttestation_WrongSecret_DeletesSession(t *testing.T) {
	// After a wrong secret attempt, the session must be deleted to prevent brute-force.
	const validSID = "deadbeefcafe0000deadbeefcafe0000deadbeefcafe0000deadbeefcafe0000"
	s := &Server{attestationSessions: NewAttestationSessionStore()}
	require.NoError(t, s.attestationSessions.Put(validSID, AttestationSession{
		ExpectedSecret: []byte("correct"),
		ExpiresAt:      time.Now().Add(time.Minute),
	}))
	req := &proto.CompleteTPMAttestationRequest{
		SessionId:       validSID,
		ActivatedSecret: []byte("wrong"),
	}
	_, _ = s.CompleteTPMAttestation(context.Background(), req)

	_, ok := s.attestationSessions.Get(validSID)
	assert.False(t, ok, "session must be deleted after wrong secret to prevent brute-force")
}

// ─── makeCredentialBlob tests ─────────────────────────────────────────────────

func TestMakeCredentialBlob_ECDSAKey_ProducesBlob(t *testing.T) {
	// Verifies that makeCredentialBlob produces a structurally valid
	// [uint16BE(len(idObject)) | idObject | uint16BE(len(encSecret)) | encSecret] blob.
	_, ekKey := buildSelfSignedCertPEM(t)
	_, akKey := buildSelfSignedCertPEM(t)

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	blob, err := makeCredentialBlob(&ekKey.PublicKey, &akKey.PublicKey, secret)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(blob), 4, "blob must have at least two uint16 length headers")

	// Verify internal structure: parse the two length-prefixed segments.
	idLen := int(blob[0])<<8 | int(blob[1])
	require.GreaterOrEqual(t, len(blob), 2+idLen+2, "blob too short for idObject segment")
	encSecretOffset := 2 + idLen
	encLen := int(blob[encSecretOffset])<<8 | int(blob[encSecretOffset+1])
	require.Equal(t, len(blob), encSecretOffset+2+encLen, "blob length does not match parsed segment lengths")
	assert.Greater(t, idLen, 0, "idObject must not be empty")
	assert.Greater(t, encLen, 0, "encSecret must not be empty")
}

// ─── BeginTPMAttestation additional validation tests ─────────────────────────

func TestBeginTPMAttestation_RSAAKKey_ReturnsInvalidArgument(t *testing.T) {
	// Non-ECDSA AK key must be rejected with InvalidArgument.
	s := &Server{
		attestationSessions: NewAttestationSessionStore(),
		accountManager: &testAccountManager{
			accountID: "acct-test",
			settings:  &types.Settings{DeviceAuth: &types.DeviceAuthSettings{CertValidityDays: 365}},
			st:        &testAttestationStore{},
		},
	}
	ekCertPEM, _ := buildSelfSignedCertPEM(t)

	// Build an RSA AK pub PEM.
	rsaKey, err := generateRSAKeyForTest(t)
	require.NoError(t, err)

	_, err = s.BeginTPMAttestation(context.Background(), &proto.BeginTPMAttestationRequest{
		EkCertPem: ekCertPEM,
		AkPubPem:  rsaKey,
		CsrPem:    buildCSRPEM(t),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "ECDSA")
}

func TestBeginTPMAttestation_ValidKeys_ProducesSession(t *testing.T) {
	// Valid EK cert + AK pub + CSR must create a session and return credential blob.
	// The session must record the WireGuard public key (from CSR CommonName) for
	// use by CompleteTPMAttestation when issuing the certificate.
	s := &Server{
		attestationSessions: NewAttestationSessionStore(),
		accountManager: &testAccountManager{
			accountID: "acct-test",
			settings:  &types.Settings{DeviceAuth: &types.DeviceAuthSettings{CertValidityDays: 365}},
			st:        &testAttestationStore{},
		},
	}
	ekCertPEM, _ := buildSelfSignedCertPEM(t)
	_, akKey := buildSelfSignedCertPEM(t)
	csrPEM := buildCSRPEM(t) // CN = "test-peer"

	resp, err := s.BeginTPMAttestation(context.Background(), &proto.BeginTPMAttestationRequest{
		EkCertPem: ekCertPEM,
		AkPubPem:  buildPublicKeyPEM(t, akKey),
		CsrPem:    csrPEM,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetSessionId())
	assert.NotEmpty(t, resp.GetCredentialBlob())

	// Verify WGKey was stored in the session.
	sess, ok := s.attestationSessions.Get(resp.GetSessionId())
	require.True(t, ok, "session must exist after BeginTPMAttestation")
	assert.Equal(t, "test-peer", sess.WGKey, "session must record WireGuard key from CSR CN")
	assert.Equal(t, csrPEM, sess.CSRPEM, "session must record CSR PEM")
}

func TestBeginTPMAttestation_EmptyCSRCommonName_ReturnsError(t *testing.T) {
	// A CSR with an empty CommonName (WireGuard key) must be rejected.
	// Note: empty CN is caught before the account lookup, so no accountManager needed.
	s := &Server{attestationSessions: NewAttestationSessionStore()}
	ekCertPEM, _ := buildSelfSignedCertPEM(t)
	_, akKey := buildSelfSignedCertPEM(t)

	csrPEM := buildCSRPEMWithCN(t, "") // empty CN

	_, err := s.BeginTPMAttestation(context.Background(), &proto.BeginTPMAttestationRequest{
		EkCertPem: ekCertPEM,
		AkPubPem:  buildPublicKeyPEM(t, akKey),
		CsrPem:    csrPEM,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "CommonName")
}

func TestAttestAppleSE_EmptyChain_ReturnsError(t *testing.T) {
	s := &Server{attestationSessions: NewAttestationSessionStore()}
	req := &proto.AttestAppleSERequest{
		CsrPem:          buildCSRPEM(t),
		AttestationPems: []string{},
	}
	_, err := s.AttestAppleSE(context.Background(), req)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// writeTempPEM writes a PEM string to a temp file and returns its path.
func writeTempPEM(t *testing.T, pemData string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "cert*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(pemData)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestAttestAppleSE_LeafOnly_FailsWithoutIntermediate(t *testing.T) {
	// When only the leaf is sent and no intermediate is configured, chain verification
	// must fail (fail-closed — never skip on missing intermediate).
	chain := buildTestCertChain(t)

	s := &Server{
		attestationSessions: NewAttestationSessionStore(),
		appleSEConfig: appleroots.Config{
			CACertFile: writeTempPEM(t, chain.RootPEM),
			// IntermediateCACertFile intentionally not set
		},
	}

	csrPEM := buildCSRPEMWithKey(t, chain.LeafKey)
	req := &proto.AttestAppleSERequest{
		CsrPem:          csrPEM,
		AttestationPems: []string{chain.LeafPEM}, // leaf only — no intermediate
	}
	_, err := s.AttestAppleSE(context.Background(), req)
	require.Error(t, err, "chain verification must fail when intermediate is missing")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAttestAppleSE_LeafPlusIntermediateInChain_Succeeds(t *testing.T) {
	// When the client includes the intermediate in the attestation_pems chain,
	// verification must succeed without an IntermediateCACertFile, and a device
	// certificate must be issued.
	chain := buildTestCertChain(t)

	s := &Server{
		attestationSessions: NewAttestationSessionStore(),
		appleSEConfig: appleroots.Config{
			CACertFile: writeTempPEM(t, chain.RootPEM),
		},
		accountManager: &testAccountManager{
			accountID: "acct-test",
			settings:  &types.Settings{DeviceAuth: &types.DeviceAuthSettings{CertValidityDays: 365}},
			st:        &testAttestationStore{},
		},
		config: &nbconfig.Config{},
	}

	csrPEM := buildCSRPEMWithKey(t, chain.LeafKey)
	req := &proto.AttestAppleSERequest{
		CsrPem:          csrPEM,
		AttestationPems: []string{chain.LeafPEM, chain.IntermediatePEM},
	}
	resp, err := s.AttestAppleSE(context.Background(), req)
	require.NoError(t, err, "full chain [leaf, intermediate] must verify against root")
	assert.Equal(t, "approved", resp.GetStatus())
	assert.NotEmpty(t, resp.GetDeviceCertPem(), "a device certificate must be issued")
	assert.NotEmpty(t, resp.GetEnrollmentId(), "an enrollment ID must be returned")
}

func TestAttestAppleSE_ConfiguredIntermediate_Succeeds(t *testing.T) {
	// When the server has IntermediateCACertFile configured and the client sends only
	// the leaf cert, verification must succeed and a device certificate must be issued.
	chain := buildTestCertChain(t)

	s := &Server{
		attestationSessions: NewAttestationSessionStore(),
		appleSEConfig: appleroots.Config{
			CACertFile:             writeTempPEM(t, chain.RootPEM),
			IntermediateCACertFile: writeTempPEM(t, chain.IntermediatePEM),
		},
		accountManager: &testAccountManager{
			accountID: "acct-test",
			settings:  &types.Settings{DeviceAuth: &types.DeviceAuthSettings{CertValidityDays: 365}},
			st:        &testAttestationStore{},
		},
		config: &nbconfig.Config{},
	}

	csrPEM := buildCSRPEMWithKey(t, chain.LeafKey)
	req := &proto.AttestAppleSERequest{
		CsrPem:          csrPEM,
		AttestationPems: []string{chain.LeafPEM}, // leaf only; intermediate comes from config
	}
	resp, err := s.AttestAppleSE(context.Background(), req)
	require.NoError(t, err, "leaf-only chain must verify when IntermediateCACertFile is configured")
	assert.Equal(t, "approved", resp.GetStatus())
	assert.NotEmpty(t, resp.GetDeviceCertPem(), "a device certificate must be issued")
	assert.NotEmpty(t, resp.GetEnrollmentId(), "an enrollment ID must be returned")
}

func TestAttestAppleSE_KeyMismatch_ReturnsInvalidArgument(t *testing.T) {
	// CSR key does not match the attestation leaf certificate key → InvalidArgument.
	chain := buildTestCertChain(t)

	s := &Server{
		attestationSessions: NewAttestationSessionStore(),
		appleSEConfig: appleroots.Config{
			CACertFile:             writeTempPEM(t, chain.RootPEM),
			IntermediateCACertFile: writeTempPEM(t, chain.IntermediatePEM),
		},
	}

	// Build CSR with a DIFFERENT key than the leaf cert.
	_, differentKey := buildSelfSignedCertPEM(t)
	csrPEM := buildCSRPEMWithKey(t, differentKey)

	req := &proto.AttestAppleSERequest{
		CsrPem:          csrPEM,
		AttestationPems: []string{chain.LeafPEM},
	}
	_, err := s.AttestAppleSE(context.Background(), req)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "does not match")
}
