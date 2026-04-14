package grpc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/devicepki/appleroots"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	attestationSessionTTL  = 5 * time.Minute
	attestationSecretBytes = 32

	// maxPEMInputSize is the maximum accepted byte length for any single PEM field
	// (EK cert, AK pub, CSR, attestation chain element). Generous for any real cert/key/CSR.
	maxPEMInputSize = 16 * 1024 // 16 KiB
	// maxAttestationChainLength is the maximum number of certs in an attestation_pems array.
	maxAttestationChainLength = 10

	// sessionIDLen is the expected length of a session ID: 32 random bytes encoded as 64 hex chars.
	sessionIDLen = 64

	// defaultCertValidityDays is used when the account has no explicit CertValidityDays configured.
	defaultCertValidityDays = 365
)

// BeginTPMAttestation starts the two-round TPM 2.0 credential activation flow.
//
// The server validates the EK certificate chain, derives the EK public key, wraps a
// freshly-generated random secret with the EK public key (RSA-OAEP for RSA keys,
// ECDH+AES-GCM for EC keys), stores the plaintext secret in an expiring session, and
// returns the session ID together with the encrypted credential blob.
//
// The client must decrypt the blob with the TPM (ActivateCredential) and return the
// plaintext secret via CompleteTPMAttestation to prove TPM possession.
func (s *Server) BeginTPMAttestation(ctx context.Context, req *proto.BeginTPMAttestationRequest) (*proto.BeginTPMAttestationResponse, error) {
	// Validate all required fields up-front before any parsing or crypto work.
	if req.GetEkCertPem() == "" || req.GetAkPubPem() == "" || req.GetCsrPem() == "" {
		return nil, status.Error(codes.InvalidArgument, "ek_cert_pem, ak_pub_pem, and csr_pem are required")
	}
	if len(req.GetEkCertPem()) > maxPEMInputSize {
		return nil, status.Errorf(codes.InvalidArgument, "ek_cert_pem exceeds maximum size (%d bytes)", maxPEMInputSize)
	}
	if len(req.GetAkPubPem()) > maxPEMInputSize {
		return nil, status.Errorf(codes.InvalidArgument, "ak_pub_pem exceeds maximum size (%d bytes)", maxPEMInputSize)
	}
	if len(req.GetCsrPem()) > maxPEMInputSize {
		return nil, status.Errorf(codes.InvalidArgument, "csr_pem exceeds maximum size (%d bytes)", maxPEMInputSize)
	}

	// Parse the CSR early to extract the WireGuard public key (Subject.CommonName).
	// We need wgKey before calling GetAccountIDForPeerKey so we can fail fast
	// (before expensive EK crypto) when the peer is not yet registered.
	csr, err := parseCSRPEM(req.GetCsrPem())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}
	// The WireGuard public key is placed in the CSR's Subject CommonName by the client
	// (see enrollment/manager.go buildCSR). Store it in the session so that
	// CompleteTPMAttestation can look up the account and issue the certificate.
	wgKey := csr.Subject.CommonName
	if wgKey == "" {
		return nil, status.Error(codes.InvalidArgument, "CSR Subject.CommonName (WireGuard public key) must not be empty")
	}

	// Resolve account ID before doing expensive crypto — fail fast if the peer
	// has not registered via a setup key yet.
	var accountID string
	if s.accountManager != nil {
		var acctErr error
		accountID, acctErr = s.accountManager.GetAccountIDForPeerKey(ctx, wgKey)
		if acctErr != nil {
			log.WithContext(ctx).Debugf("BeginTPMAttestation: peer %s not registered: %v", wgKey, acctErr)
			return nil, status.Error(codes.NotFound, "peer not registered; use a setup key to register before attesting")
		}
	}

	ekCert, err := parseCertPEM(req.GetEkCertPem())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid EK certificate: %v", err)
	}

	// Verify EK cert against bundled TPM manufacturer CA pool.
	// When no manufacturer CAs are bundled (development / open-source build) the
	// check is skipped with a warning; AK↔EK binding is still enforced by the
	// MakeCredential/ActivateCredential protocol itself.
	skipped, ekErr := devicepki.VerifyEKCertChain(ekCert)
	if ekErr != nil {
		log.WithContext(ctx).Warnf("BeginTPMAttestation: EK chain verification failed: %v", ekErr)
		return nil, status.Errorf(codes.Unauthenticated, "EK certificate chain verification failed: %v", ekErr)
	}
	if skipped {
		log.WithContext(ctx).Warn("BeginTPMAttestation: no TPM manufacturer CA certs bundled — EK chain verification skipped (development mode)")
	}

	akPubCrypto, err := parsePublicKeyPEM(req.GetAkPubPem())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid AK public key: %v", err)
	}
	akECDSA, ok := akPubCrypto.(*ecdsa.PublicKey)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "AK public key must be ECDSA (EC P-256)")
	}

	secret := make([]byte, attestationSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		log.WithContext(ctx).Errorf("BeginTPMAttestation: generate secret: %v", err)
		return nil, status.Error(codes.Internal, "failed to generate attestation secret")
	}

	credentialBlob, err := makeCredentialBlob(ekCert.PublicKey, akECDSA, secret)
	if err != nil {
		log.WithContext(ctx).Errorf("BeginTPMAttestation: make credential blob: %v", err)
		return nil, status.Error(codes.Internal, "failed to create credential challenge")
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate session ID")
	}

	if err := s.attestationSessions.Put(sessionID, AttestationSession{
		ExpectedSecret: secret,
		CSRPEM:         req.GetCsrPem(),
		WGKey:          wgKey,
		AccountID:      accountID,
		ExpiresAt:      time.Now().Add(attestationSessionTTL),
	}); err != nil {
		log.WithContext(ctx).Warnf("BeginTPMAttestation: session store at capacity: %v", err)
		return nil, status.Error(codes.ResourceExhausted, "attestation session store at capacity, retry later")
	}

	log.WithContext(ctx).Debugf("BeginTPMAttestation: session %s… created", sessionID[:8])

	return &proto.BeginTPMAttestationResponse{
		SessionId:      sessionID,
		CredentialBlob: credentialBlob,
	}, nil
}

// CompleteTPMAttestation finishes the two-round TPM credential activation flow.
//
// The client must return the plaintext secret obtained by calling TPM2_ActivateCredential
// on the credential blob returned by BeginTPMAttestation. On success the pending enrollment
// is updated to Approved and a signed device certificate is returned.
func (s *Server) CompleteTPMAttestation(ctx context.Context, req *proto.CompleteTPMAttestationRequest) (*proto.AttestationResult, error) {
	// Validate session ID format before any lookup to prevent log injection and
	// index-out-of-range panics on short / malformed IDs.
	sid := req.GetSessionId()
	if !isValidSessionID(sid) {
		return nil, status.Error(codes.InvalidArgument, "invalid session ID format")
	}
	sidShort := sid[:8]

	// GetAndDelete is atomic: it retrieves and removes the session under a single
	// write lock. This prevents a TOCTOU race where two concurrent requests with
	// the same session ID could both pass the existence check and each issue a cert.
	sess, ok := s.attestationSessions.GetAndDelete(sid)
	if !ok {
		return nil, status.Error(codes.NotFound, "attestation session not found or expired")
	}

	// Constant-time comparison to prevent timing oracle attacks.
	// The session is already consumed (deleted) regardless of the outcome —
	// wrong secret attempts cannot be retried with the same session.
	if subtle.ConstantTimeCompare(sess.ExpectedSecret, req.GetActivatedSecret()) != 1 {
		log.WithContext(ctx).Warnf("CompleteTPMAttestation: wrong secret for session %s… — session invalidated", sidShort)
		return nil, status.Error(codes.PermissionDenied, "activated secret does not match — session invalidated")
	}

	log.WithContext(ctx).Debugf("CompleteTPMAttestation: session %s… verified", sidShort)

	result, err := s.issueDeviceCert(ctx, sess.AccountID, sess.WGKey, sess.CSRPEM, "")
	if err != nil {
		return nil, err
	}
	return result, nil
}

// AttestAppleSE performs a single-round Apple Secure Enclave attestation.
//
// The client submits the attestation certificate chain together with a CSR whose
// public key must match the leaf attestation certificate. The server verifies the
// chain against the Apple Root CA G3 pool plus any configured intermediate CAs and,
// on success, issues a device certificate from the built-in CA.
//
// Production note: Apple's SecKeyCreateAttestation returns only the leaf certificate.
// The leaf is signed by an Apple Secure Key Attestation intermediate CA, not directly
// by the Apple Root CA G3. For chain verification to succeed the operator must either:
//   - Configure appleSEConfig.IntermediateCACertFile with the Apple Secure Key
//     Attestation CA PEM (download from https://www.apple.com/certificateauthority/)
//   - Or ensure the client sends the full chain including the intermediate cert.
//
// Verification fails (not skipped) when the intermediate is missing.
func (s *Server) AttestAppleSE(ctx context.Context, req *proto.AttestAppleSERequest) (*proto.AttestationResult, error) {
	if len(req.GetAttestationPems()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "attestation_pems must not be empty")
	}
	if len(req.GetAttestationPems()) > maxAttestationChainLength {
		return nil, status.Errorf(codes.InvalidArgument, "attestation_pems chain too long (max %d)", maxAttestationChainLength)
	}
	if len(req.GetCsrPem()) > maxPEMInputSize {
		return nil, status.Errorf(codes.InvalidArgument, "csr_pem exceeds maximum size (%d bytes)", maxPEMInputSize)
	}
	for i, p := range req.GetAttestationPems() {
		if len(p) > maxPEMInputSize {
			return nil, status.Errorf(codes.InvalidArgument, "attestation_pems[%d] exceeds maximum size (%d bytes)", i, maxPEMInputSize)
		}
	}

	csr, err := parseCSRPEM(req.GetCsrPem())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}
	// The WireGuard public key must be in the CSR Subject CommonName (same requirement
	// as BeginTPMAttestation). Reject early to avoid doing crypto work on invalid input.
	wgKey := csr.Subject.CommonName
	if wgKey == "" {
		return nil, status.Error(codes.InvalidArgument, "CSR Subject.CommonName (WireGuard public key) must not be empty")
	}

	// Fail-fast: resolve account before expensive chain verification and root pool loading.
	// Consistent with BeginTPMAttestation which does the same before MakeCredential crypto.
	var accountID string
	if s.accountManager != nil {
		var acctErr error
		accountID, acctErr = s.accountManager.GetAccountIDForPeerKey(ctx, wgKey)
		if acctErr != nil {
			log.WithContext(ctx).Debugf("AttestAppleSE: peer %s not registered: %v", wgKey, acctErr)
			return nil, status.Error(codes.NotFound, "peer not registered; use a setup key to register before attesting")
		}
	}

	chain, err := parseAttestationChain(req.GetAttestationPems())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid attestation chain: %v", err)
	}

	rootPool, err := appleroots.BuildAppleSERootPool(ctx, s.appleSEConfig)
	if err != nil {
		log.WithContext(ctx).Errorf("AttestAppleSE: build Apple root pool: %v", err)
		return nil, status.Error(codes.Internal, "failed to load Apple root CA pool")
	}

	// Load operator-configured intermediate CAs (Apple Secure Key Attestation CA).
	// Returns nil (no error) when IntermediateCACertFile is not set.
	configuredIntermediates, err := appleroots.LoadIntermediateCerts(s.appleSEConfig)
	if err != nil {
		log.WithContext(ctx).Errorf("AttestAppleSE: load intermediate CAs: %v", err)
		return nil, status.Error(codes.Internal, "failed to load Apple intermediate CA pool")
	}

	if err := verifyAppleAttestationChain(chain, rootPool, configuredIntermediates); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "attestation chain verification failed: %v", err)
	}

	if err := matchCSRAndLeafKey(csr, chain[0]); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "CSR public key does not match attestation leaf certificate: %v", err)
	}

	log.WithContext(ctx).Debugf("AttestAppleSE: chain verified, %d certs", len(chain))

	return s.issueDeviceCert(ctx, accountID, wgKey, req.GetCsrPem(), req.GetSystemInfo())
}

// parseAttestationChain decodes a slice of PEM-encoded certificate strings into
// []*x509.Certificate. Returns an error when any PEM block is invalid or contains
// no parseable certificate.
func parseAttestationChain(pems []string) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(pems))
	for i, p := range pems {
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			return nil, fmt.Errorf("attestation cert %d: PEM decode failed", i)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attestation cert %d: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// verifyAppleAttestationChain verifies that the attestation chain is signed by one of
// the roots in rootPool.
//
// The leaf is chain[0]. chain[1:] (if any) are treated as chain-provided intermediates.
// configuredIntermediates are additional intermediate CAs loaded from the operator's
// IntermediateCACertFile (e.g. Apple Secure Key Attestation CA 1/3). May be nil.
//
// All intermediates — both chain-provided and configured — are added to
// x509.VerifyOptions.Intermediates so that Go can build the chain to the root.
//
// Returns a clear error when intermediate CAs are missing and the leaf cannot be
// verified directly against the root (fail-closed behaviour — no silent skip).
func verifyAppleAttestationChain(chain []*x509.Certificate, rootPool *x509.CertPool, configuredIntermediates []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty attestation chain")
	}
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: x509.NewCertPool(),
	}
	// Add chain-provided certs (chain[1:]) as intermediates.
	for _, c := range chain[1:] {
		opts.Intermediates.AddCert(c)
	}
	// Add operator-configured intermediate CAs (e.g. Apple Secure Key Attestation CA).
	for _, c := range configuredIntermediates {
		opts.Intermediates.AddCert(c)
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// matchCSRAndLeafKey verifies that the CSR public key matches the public key in the
// leaf attestation certificate. This binds the CSR to the attested key.
func matchCSRAndLeafKey(csr *x509.CertificateRequest, leaf *x509.Certificate) error {
	csrDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CSR public key: %w", err)
	}
	leafDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal leaf public key: %w", err)
	}
	if !bytes.Equal(csrDER, leafDER) {
		return fmt.Errorf("key mismatch")
	}
	return nil
}

// isValidSessionID reports whether id is a valid attestation session ID:
// exactly sessionIDLen lowercase hex characters generated by generateSessionID.
// Used to prevent log injection and index-out-of-range panics on malformed inputs.
func isValidSessionID(id string) bool {
	if len(id) != sessionIDLen {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// issueDeviceCert resolves the account, creates/loads the CA, signs the CSR,
// and persists the certificate and enrollment record. It is called by both
// CompleteTPMAttestation and AttestAppleSE after their respective attestation
// checks pass.
//
// If accountID is non-empty it is used directly (pre-resolved during BeginTPMAttestation).
// Otherwise, accountID is looked up from wgKey via GetAccountIDForPeerKey.
func (s *Server) issueDeviceCert(ctx context.Context, accountID, wgKey, csrPEM, systemInfo string) (*proto.AttestationResult, error) {
	if accountID == "" {
		var err error
		accountID, err = s.accountManager.GetAccountIDForPeerKey(ctx, wgKey)
		if err != nil {
			log.WithContext(ctx).Warnf("issueDeviceCert: peer %s not registered: %v", wgKey, err)
			return nil, status.Errorf(codes.NotFound, "peer not registered; use a setup key to register before attesting")
		}
	}

	accountSettings, err := s.accountManager.GetAccountSettings(ctx, accountID, "")
	if err != nil {
		log.WithContext(ctx).Errorf("issueDeviceCert: get account settings for %s: %v", accountID, err)
		return nil, status.Error(codes.Internal, "failed to load account settings")
	}

	csr, err := parseCSRPEM(csrPEM)
	if err != nil {
		log.WithContext(ctx).Errorf("issueDeviceCert: parse CSR for peer %s: %v", wgKey, err)
		return nil, status.Error(codes.Internal, "failed to parse stored CSR")
	}

	ca, err := devicepki.NewCA(ctx, accountSettings.DeviceAuth, accountID, s.accountManager.GetStore(), s.config.ManagementURL)
	if err != nil {
		log.WithContext(ctx).Errorf("issueDeviceCert: load CA for account %s: %v", accountID, err)
		return nil, status.Error(codes.Internal, "failed to load certificate authority")
	}

	validityDays := defaultCertValidityDays
	if accountSettings.DeviceAuth != nil && accountSettings.DeviceAuth.CertValidityDays > 0 {
		validityDays = accountSettings.DeviceAuth.CertValidityDays
	}

	cert, err := ca.SignCSR(ctx, csr, wgKey, validityDays)
	if err != nil {
		log.WithContext(ctx).Errorf("issueDeviceCert: sign CSR for peer %s: %v", wgKey, err)
		return nil, status.Error(codes.Internal, "failed to sign device certificate")
	}

	certPEMStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	st := s.accountManager.GetStore()

	// Best-effort peer ID lookup — peerID is informational metadata; cert issuance succeeds either way.
	var peerID string
	if peer, peerErr := st.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, wgKey); peerErr == nil && peer != nil {
		peerID = peer.ID
	}

	newDevCert := types.NewDeviceCertificate(
		accountID, peerID, wgKey,
		cert.SerialNumber.String(), certPEMStr,
		cert.NotBefore, cert.NotAfter,
	)
	if saveErr := st.SaveDeviceCertificate(ctx, store.LockingStrengthUpdate, newDevCert); saveErr != nil {
		log.WithContext(ctx).Errorf("issueDeviceCert: save cert for peer %s: %v", wgKey, saveErr)
		return nil, status.Error(codes.Internal, "failed to save device certificate")
	}

	newReq := types.NewEnrollmentRequest(accountID, peerID, wgKey, csrPEM, systemInfo)
	newReq.Status = types.EnrollmentStatusApproved
	if saveErr := st.SaveEnrollmentRequest(ctx, store.LockingStrengthUpdate, newReq); saveErr != nil {
		log.WithContext(ctx).Warnf("issueDeviceCert: save enrollment record for peer %s: %v", wgKey, saveErr)
	}

	log.WithContext(ctx).Infof("issueDeviceCert: issued cert serial %s for peer %s (expires %s)",
		cert.SerialNumber, wgKey, cert.NotAfter.Format("2006-01-02"))

	return &proto.AttestationResult{
		EnrollmentId:  newReq.ID,
		Status:        types.EnrollmentStatusApproved,
		DeviceCertPem: certPEMStr,
	}, nil
}

// parseCertPEM decodes a single PEM certificate block and parses it as an x509.Certificate.
func parseCertPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePublicKeyPEM decodes a PEM-encoded PKIX public key (SubjectPublicKeyInfo).
func parsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// ekAuthPolicy returns the standard TCG EK credential profile authPolicy digest.
// It is SHA-256(SHA-256(zeros32 || TPM2_PolicySecret(TPM_RH_ENDORSEMENT, emptyRef))).
func ekAuthPolicy() []byte {
	policy, _ := hex.DecodeString("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")
	return policy
}

// padTo32 zero-pads b to exactly 32 bytes (for P-256 coordinates).
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// ekTPMPublic constructs a *tpm2.TPMTPublic for a standard TCG EK from the cert's public key.
// Supports RSA-2048 and P-256 ECC EKs.
func ekTPMPublic(ekPub crypto.PublicKey, x, y []byte, n []byte) (*tpm2.TPMTPublic, error) {
	authPolicy := ekAuthPolicy()
	attrs := tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		AdminWithPolicy:     true,
		Restricted:          true,
		Decrypt:             true,
	}
	symDef := tpm2.TPMTSymDefObject{
		Algorithm: tpm2.TPMAlgAES,
		KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
		Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
	}

	switch ekPub.(type) {
	case *ecdsa.PublicKey:
		pub := &tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgECC,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: attrs,
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: authPolicy},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Symmetric: symDef,
				CurveID:   tpm2.TPMECCNistP256,
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: padTo32(x)},
				Y: tpm2.TPM2BECCParameter{Buffer: padTo32(y)},
			}),
		}
		return pub, nil
	case *rsa.PublicKey:
		pub := &tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgRSA,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: attrs,
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: authPolicy},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Symmetric: symDef,
				// Scheme left zero (nullable → TPMAlgNull)
				KeyBits:  2048,
				Exponent: 0, // 0 means 65537
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: n}),
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported EK public key type %T", ekPub)
	}
}

// akTPMPublic reconstructs the server's expected *tpm2.TPMTPublic for the Linux AK.
// The AK is an ECC P-256 restricted signing key created in the Owner hierarchy.
// Template must match loadOrCreateAK in tpm_linux.go exactly.
func akTPMPublic(akPub *ecdsa.PublicKey) *tpm2.TPMTPublic {
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
				),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: padTo32(akPub.X.Bytes())},
			Y: tpm2.TPM2BECCParameter{Buffer: padTo32(akPub.Y.Bytes())},
		}),
	}
}

// makeCredentialBlob implements TPM2_MakeCredential in pure software using go-tpm's
// CreateCredential function. It wraps the secret such that only the client TPM can
// recover it by calling TPM2_ActivateCredential with the matching EK and AK.
//
// Returns [uint16BE(len(idObject)) | idObject | uint16BE(len(encSecret)) | encSecret].
func makeCredentialBlob(ekPub crypto.PublicKey, akPub *ecdsa.PublicKey, secret []byte) ([]byte, error) {
	var (
		x, y []byte
		n    []byte
	)
	switch k := ekPub.(type) {
	case *ecdsa.PublicKey:
		x, y = k.X.Bytes(), k.Y.Bytes()
	case *rsa.PublicKey:
		n = k.N.Bytes()
	}
	ekTPM, err := ekTPMPublic(ekPub, x, y, n)
	if err != nil {
		return nil, fmt.Errorf("build EK TPMTPublic: %w", err)
	}

	encapKey, err := tpm2.ImportEncapsulationKey(ekTPM)
	if err != nil {
		return nil, fmt.Errorf("import EK encapsulation key: %w", err)
	}

	// Compute AK name from the reconstructed TPMTPublic.
	akTPM := akTPMPublic(akPub)
	akName, err := tpm2.ObjectName(akTPM)
	if err != nil {
		return nil, fmt.Errorf("compute AK name: %w", err)
	}

	idObject, encSecret, err := tpm2.CreateCredential(rand.Reader, encapKey, akName.Buffer, secret)
	if err != nil {
		return nil, fmt.Errorf("CreateCredential: %w", err)
	}

	// Combine: uint16BE(len(idObject)) | idObject | uint16BE(len(encSecret)) | encSecret
	blob := make([]byte, 2+len(idObject)+2+len(encSecret))
	binary.BigEndian.PutUint16(blob[0:2], uint16(len(idObject)))
	copy(blob[2:], idObject)
	binary.BigEndian.PutUint16(blob[2+len(idObject):], uint16(len(encSecret)))
	copy(blob[4+len(idObject):], encSecret)
	return blob, nil
}

// generateSessionID creates a cryptographically random 32-byte hex session token.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
