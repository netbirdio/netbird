//go:build linux

package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

const (
	linuxTPMDevice       = "/dev/tpmrm0"
	linuxTPMDeviceLegacy = "/dev/tpm0"
	persistentHandle     = tpm2.TPMHandle(0x81000001) // device signing key
	akPersistentHandle   = tpm2.TPMHandle(0x81000002) // attestation key
	ekCertNVIndexEC      = tpm2.TPMHandle(0x01C0000A)
	ekCertNVIndexRSA     = tpm2.TPMHandle(0x01C00002)
)

// linuxProvider implements Provider using TPM 2.0 via github.com/google/go-tpm.
// Private keys are bound to TPM persistent handles and never exported.
// Device certificates are stored as PEM files in stateDir.
type linuxProvider struct {
	mu       sync.Mutex
	stateDir string
}

// NewPlatformProvider returns a TPM 2.0-backed Provider on Linux.
// If no stateDir is supplied, /var/lib/netbird is used.
func NewPlatformProvider(stateDir ...string) Provider {
	dir := "/var/lib/netbird"
	if len(stateDir) > 0 && stateDir[0] != "" {
		dir = stateDir[0]
	}
	return &linuxProvider{stateDir: dir}
}

func (p *linuxProvider) Available() bool {
	if os.Getenv("NETBIRD_TPM_SIMULATOR") != "" {
		return true
	}
	if _, err := os.Stat(linuxTPMDevice); err == nil {
		return true
	}
	_, err := os.Stat(linuxTPMDeviceLegacy)
	return err == nil
}

func (p *linuxProvider) openTPM() (transport.TPMCloser, error) {
	if sim := os.Getenv("NETBIRD_TPM_SIMULATOR"); sim != "" {
		// NETBIRD_TPM_SIMULATOR must be "host:commandPort,host:platformPort" or
		// a single "host:commandPort" (platform port defaults to commandPort+1).
		cmdAddr, platAddr, err := splitSimulatorAddr(sim)
		if err != nil {
			return nil, fmt.Errorf("tpm: invalid NETBIRD_TPM_SIMULATOR %q: %w", sim, err)
		}
		t, err := tcp.Open(tcp.Config{
			CommandAddress:  cmdAddr,
			PlatformAddress: platAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("tpm: open TCP simulator at %q: %w", sim, err)
		}
		return t, nil
	}
	if _, err := os.Stat(linuxTPMDevice); err == nil {
		return transport.OpenTPM(linuxTPMDevice)
	}
	return transport.OpenTPM(linuxTPMDeviceLegacy)
}

// splitSimulatorAddr parses NETBIRD_TPM_SIMULATOR into command and platform addresses.
// Accepts "host:cmdPort,host:platPort" or "host:cmdPort" (platform = cmdPort+1).
func splitSimulatorAddr(sim string) (cmdAddr, platAddr string, err error) {
	parts := strings.SplitN(sim, ",", 2)
	cmdAddr = parts[0]
	if len(parts) == 2 {
		platAddr = parts[1]
		return
	}
	// Derive platform port by incrementing command port by 1.
	host, portStr, splitErr := net.SplitHostPort(cmdAddr)
	if splitErr != nil {
		return "", "", splitErr
	}
	portNum, parseErr := strconv.Atoi(portStr)
	if parseErr != nil {
		return "", "", fmt.Errorf("invalid port %q: %w", portStr, parseErr)
	}
	platAddr = net.JoinHostPort(host, strconv.Itoa(portNum+1))
	return
}

// GenerateKey creates or returns an EC P-256 key at the fixed persistent handle.
// The operation is idempotent: if a key already exists at persistentHandle,
// the existing key is returned without creating a new one.
func (p *linuxProvider) GenerateKey(_ context.Context, keyID string) (crypto.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	t, err := p.openTPM()
	if err != nil {
		return nil, fmt.Errorf("tpm: open device: %w", err)
	}
	defer t.Close()

	// Try to load the persistent key first (idempotent).
	if signer, err := p.loadFromHandle(t); err == nil {
		return signer, nil
	}

	// Build an EC P-256 primary key template bound to the TPM.
	eccParms := tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		CurveID: tpm2.TPMECCNistP256,
	}
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &eccParms),
		Unique:     tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}

	createCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(pub),
	}
	rsp, err := createCmd.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: create primary key: %w", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		_, _ = flush.Execute(t)
	}()

	// Persist the key so it survives reboots.
	evict := tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     rsp.ObjectHandle,
		PersistentHandle: persistentHandle,
	}
	if _, err = evict.Execute(t); err != nil {
		return nil, fmt.Errorf("tpm: persist key at handle 0x%x: %w", persistentHandle, err)
	}

	ecPub, err := ecPublicFromTPM(rsp.OutPublic)
	if err != nil {
		return nil, err
	}
	return &tpmSigner{provider: p, pub: ecPub}, nil
}

func (p *linuxProvider) LoadKey(_ context.Context, keyID string) (crypto.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	t, err := p.openTPM()
	if err != nil {
		return nil, fmt.Errorf("tpm: open device: %w", err)
	}
	defer t.Close()

	signer, err := p.loadFromHandle(t)
	if err != nil {
		return nil, ErrKeyNotFound
	}
	return signer, nil
}

// loadFromHandle reads the public key from persistentHandle.
// Must be called with p.mu held.
func (p *linuxProvider) loadFromHandle(t transport.TPM) (crypto.Signer, error) {
	readPub := tpm2.ReadPublic{ObjectHandle: persistentHandle}
	rsp, err := readPub.Execute(t)
	if err != nil {
		return nil, err
	}
	ecPub, err := ecPublicFromTPM(rsp.OutPublic)
	if err != nil {
		return nil, err
	}
	return &tpmSigner{provider: p, pub: ecPub}, nil
}

func (p *linuxProvider) StoreCert(_ context.Context, keyID string, cert *x509.Certificate) error {
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	if err := os.MkdirAll(p.stateDir, 0700); err != nil {
		return fmt.Errorf("tpm: create state dir: %w", err)
	}
	path := p.certPath(keyID)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("tpm: open cert file: %w", err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func (p *linuxProvider) LoadCert(_ context.Context, keyID string) (*x509.Certificate, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p.certPath(keyID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("tpm: read cert file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("tpm: invalid PEM in cert file")
	}
	return x509.ParseCertificate(block.Bytes)
}

// AttestationProof collects the full TPM 2.0 attestation bundle:
//   - EKCert: DER-encoded EK certificate from TPM NV storage
//   - AKPublic: PKIX DER of the persistent Attestation Key
//   - CertifyInfo: raw TPM2B_ATTEST bytes from TPM2_Certify
//   - Signature: ASN.1 ECDSA signature of the AK over CertifyInfo
func (p *linuxProvider) AttestationProof(_ context.Context, _ string) (*AttestationProof, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	t, err := p.openTPM()
	if err != nil {
		return nil, fmt.Errorf("tpm: open device: %w", err)
	}
	defer t.Close()

	// 1. Read EK certificate from NV storage (EC first, then RSA).
	ekCert, err := readNVCert(t, ekCertNVIndexEC)
	if err != nil {
		ekCert, err = readNVCert(t, ekCertNVIndexRSA)
		if err != nil {
			return nil, fmt.Errorf("tpm: read EK cert from NV: %w", err)
		}
	}

	// 2. Load or create the Attestation Key (restricted signing key).
	akPub, err := p.loadOrCreateAK(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: load or create AK: %w", err)
	}

	// 3. Marshal AK public key as SubjectPublicKeyInfo DER.
	akPubDER, err := x509.MarshalPKIXPublicKey(akPub)
	if err != nil {
		return nil, fmt.Errorf("tpm: marshal AK public key: %w", err)
	}

	// 4. Use TPM2_Certify to certify the device key with the AK.
	certifyCmd := tpm2.Certify{
		ObjectHandle: tpm2.AuthHandle{Handle: persistentHandle, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:   tpm2.AuthHandle{Handle: akPersistentHandle, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: []byte("netbird-device-attestation")},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
	}
	certRsp, err := certifyCmd.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: certify device key: %w", err)
	}

	// 5. Extract and ASN.1-encode the ECDSA signature.
	eccSig, err := certRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpm: extract AK ECDSA signature: %w", err)
	}
	r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
	sigS := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)
	sigDER, err := asn1.Marshal(struct{ R, S *big.Int }{r, sigS})
	if err != nil {
		return nil, fmt.Errorf("tpm: marshal AK signature: %w", err)
	}

	return &AttestationProof{
		EKCert:      ekCert,
		AKPublic:    akPubDER,
		CertifyInfo: certRsp.CertifyInfo.Bytes(),
		Signature:   sigDER,
	}, nil
}

// ActivateCredential performs TPM2_ActivateCredential using the AK and EK.
// The credentialBlob must be in [uint16BE(idObjLen)|idObject|uint16BE(encSecLen)|encSecret] format
// as produced by the server's BeginTPMAttestation.
//
// Authorization: the EK requires a PolicySecret session over TPM_RH_ENDORSEMENT.
func (p *linuxProvider) ActivateCredential(_ context.Context, credentialBlob []byte) ([]byte, error) {
	idObject, encSecret, err := parseCredentialBlob(credentialBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm: parse credential blob: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	t, err := p.openTPM()
	if err != nil {
		return nil, fmt.Errorf("tpm: open device for ActivateCredential: %w", err)
	}
	defer t.Close()

	// Re-derive the EK from the endorsement hierarchy using the standard ECC EK template.
	// CreatePrimary is deterministic: same template + same hierarchy seed = same key.
	ekHandle, err := createEKPrimary(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: create EK primary: %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: ekHandle.ObjectHandle}.Execute(t)
	}()

	// Create a policy session for the EK's endorsement authorization.
	// The EK's authPolicy requires: PolicySecret(TPM_RH_ENDORSEMENT).
	policySess, closePolicy, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("tpm: create policy session: %w", err)
	}
	defer closePolicy()

	if _, err := (tpm2.PolicySecret{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		PolicySession: policySess.Handle(),
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("tpm: PolicySecret(RH_ENDORSEMENT): %w", err)
	}

	rsp, err := (tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: akPersistentHandle, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: ekHandle.ObjectHandle, Auth: policySess},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: idObject},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encSecret},
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: TPM2_ActivateCredential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

// createEKPrimary re-derives the ECC Endorsement Key primary using the standard TCG template.
// The EK is deterministic: the same template + endorsement hierarchy seed always produces
// the same key. The caller is responsible for flushing the returned handle.
func createEKPrimary(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	ekAttrs := tpm2.TPMAObject{
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
	ekPub := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: ekAttrs,
		AuthPolicy:       tpm2.TPM2BDigest{Buffer: standardEKAuthPolicy()},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: symDef,
			CurveID:   tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}

	rsp, err := (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(ekPub),
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("TPM2_CreatePrimary(EK): %w", err)
	}
	return rsp, nil
}

// standardEKAuthPolicy returns the standard TCG EK credential profile authPolicy.
// SHA-256(SHA-256(zeros32 || enc(TPM_CC_PolicySecret, TPM_RH_ENDORSEMENT))).
// Precomputed from Credential_Profile_EK_V2.0, section 2.1.5.3.
func standardEKAuthPolicy() []byte {
	// Decode never fails for a valid hex literal.
	policy, _ := hex.DecodeString("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")
	return policy
}

// maxCredentialBlobSize is a sanity cap: idObject ≤ 1 kB, encSecret ≤ 1 kB → 2 kB + headers.
const maxCredentialBlobSize = 4096

// parseCredentialBlob splits the combined [uint16BE(idObjLen)|idObject|uint16BE(encSecLen)|encSecret] blob.
func parseCredentialBlob(blob []byte) (idObject, encSecret []byte, err error) {
	if len(blob) < 4 {
		return nil, nil, fmt.Errorf("credential blob too short (%d bytes)", len(blob))
	}
	if len(blob) > maxCredentialBlobSize {
		return nil, nil, fmt.Errorf("credential blob too large (%d bytes)", len(blob))
	}
	idObjLen := int(binary.BigEndian.Uint16(blob[0:2]))
	if len(blob) < 2+idObjLen+2 {
		return nil, nil, fmt.Errorf("credential blob truncated: need %d bytes for id_object, have %d", idObjLen, len(blob)-4)
	}
	idObject = blob[2 : 2+idObjLen]
	encSecLen := int(binary.BigEndian.Uint16(blob[2+idObjLen : 4+idObjLen]))
	if len(blob) < 4+idObjLen+encSecLen {
		return nil, nil, fmt.Errorf("credential blob truncated: need %d bytes for enc_secret, have %d", encSecLen, len(blob)-4-idObjLen)
	}
	encSecret = blob[4+idObjLen : 4+idObjLen+encSecLen]
	return idObject, encSecret, nil
}

// loadOrCreateAK loads the Attestation Key from akPersistentHandle,
// creating and persisting it if it does not yet exist.
// Must be called with p.mu held and with a live TPM connection t.
func (p *linuxProvider) loadOrCreateAK(t transport.TPM) (*ecdsa.PublicKey, error) {
	// Try to load the existing AK via ReadPublic on the persistent handle.
	readPub := tpm2.ReadPublic{ObjectHandle: akPersistentHandle}
	if rsp, err := readPub.Execute(t); err == nil {
		if ecPub, err := ecPublicFromTPM(rsp.OutPublic); err == nil {
			return ecPub, nil
		}
	}

	// Create a restricted ECDSA P-256 primary key (the AK).
	eccParms := tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		CurveID: tpm2.TPMECCNistP256,
	}
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          true, // required for an Attestation Key
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &eccParms),
		Unique:     tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}

	createCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(pub),
	}
	rsp, err := createCmd.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: create AK primary: %w", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		_, _ = flush.Execute(t)
	}()

	// Persist the AK so it survives reboots.
	evict := tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     rsp.ObjectHandle,
		PersistentHandle: akPersistentHandle,
	}
	if _, err := evict.Execute(t); err != nil {
		return nil, fmt.Errorf("tpm: persist AK at handle 0x%x: %w", akPersistentHandle, err)
	}

	return ecPublicFromTPM(rsp.OutPublic)
}

func (p *linuxProvider) certPath(keyID string) string {
	return filepath.Join(p.stateDir, "device-"+keyID+".crt")
}

// tpmSigner is a crypto.Signer that delegates signing to TPM2_Sign.
type tpmSigner struct {
	provider *linuxProvider
	pub      *ecdsa.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("tpm: cannot sign empty digest")
	}
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	t, err := s.provider.openTPM()
	if err != nil {
		return nil, fmt.Errorf("tpm: open device for sign: %w", err)
	}
	defer t.Close()

	signCmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{Handle: persistentHandle},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}
	rsp, err := signCmd.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: sign digest: %w", err)
	}

	eccSig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpm: extract ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
	sigS := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)
	return asn1.Marshal(struct{ R, S *big.Int }{r, sigS})
}

// ecPublicFromTPM extracts an *ecdsa.PublicKey from a TPM2B_PUBLIC.
func ecPublicFromTPM(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	detail, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: parse public key contents: %w", err)
	}
	eccID, err := detail.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm: extract ECC point from public key: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(eccID.X.Buffer),
		Y:     new(big.Int).SetBytes(eccID.Y.Buffer),
	}, nil
}

// maxNVReadChunk is the maximum bytes read per NVRead command.
// The TPM spec allows implementations to cap NV reads; 1024 is a safe minimum.
const maxNVReadChunk = uint16(1024)

// readNVCert reads raw bytes from a TPM NV index (used for EK certificates).
// It reads in chunks of maxNVReadChunk to support large EK certificates (e.g. RSA 2048 EK certs
// can exceed 1200 bytes) on TPMs that cap single NVRead operations.
func readNVCert(t transport.TPM, nvIndex tpm2.TPMHandle) ([]byte, error) {
	pubCmd := tpm2.NVReadPublic{NVIndex: nvIndex}
	pubRsp, err := pubCmd.Execute(t)
	if err != nil {
		return nil, err
	}
	nvPub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: parse NV public: %w", err)
	}
	totalSize := nvPub.DataSize

	data := make([]byte, 0, totalSize)
	for offset := uint16(0); offset < totalSize; {
		chunkSize := maxNVReadChunk
		if remaining := totalSize - offset; remaining < chunkSize {
			chunkSize = remaining
		}
		readCmd := tpm2.NVRead{
			AuthHandle: tpm2.NamedHandle{Handle: tpm2.TPMRHOwner},
			NVIndex:    tpm2.NamedHandle{Handle: nvIndex},
			Size:       chunkSize,
			Offset:     offset,
		}
		readRsp, err := readCmd.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("tpm: NVRead at offset %d: %w", offset, err)
		}
		data = append(data, readRsp.Data.Buffer...)
		offset += chunkSize
	}
	return data, nil
}
