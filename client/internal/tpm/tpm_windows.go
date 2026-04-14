//go:build windows

package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// ncryptKeyContainerName is the machine-scoped CNG key container for the device key.
	ncryptKeyContainerName = "netbird-device-key"
	// ncryptProviderName selects the TPM-backed CNG provider.
	ncryptProviderName = "Microsoft Platform Crypto Provider"
	// ekCertNVIndexRSA is the TPM NV index holding the RSA Endorsement Key certificate.
	ekCertNVIndexRSA = uint32(0x01C00002)
	// ekCertNVIndexEC is the TPM NV index holding the EC Endorsement Key certificate.
	ekCertNVIndexEC = uint32(0x01C0000A)
)

var (
	ncrypt    = windows.NewLazySystemDLL("ncrypt.dll")
	tbsLib    = windows.NewLazySystemDLL("tbs.dll")
	crypt32   = windows.NewLazySystemDLL("crypt32.dll")

	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

// SECURITY_STATUS codes
const (
	ncryptSuccess         = 0x00000000
	ncryptKeyDoesNotExist = 0x80090016
	ncryptMachinekeyFlag  = 0x00000020
)

// windowsProvider implements Provider via CNG (Cryptography Next Generation).
// Keys are stored in the TPM-backed "Microsoft Platform Crypto Provider".
// Certificates are stored in the Windows Certificate Store (LocalMachine\MY).
type windowsProvider struct {
	mu       sync.Mutex
	stateDir string
}

// NewPlatformProvider returns a CNG/TPM-backed Provider on Windows.
func NewPlatformProvider(stateDir ...string) Provider {
	dir := filepath.Join(os.Getenv("ProgramData"), "Netbird")
	if len(stateDir) > 0 && stateDir[0] != "" {
		dir = stateDir[0]
	}
	return &windowsProvider{stateDir: dir}
}

func (p *windowsProvider) Available() bool {
	var hProv uintptr
	providerName, _ := syscall.UTF16PtrFromString(ncryptProviderName)
	ret, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProv)),
		uintptr(unsafe.Pointer(providerName)),
		0,
	)
	if ret == ncryptSuccess {
		_, _, _ = procNCryptFreeObject.Call(hProv)
		return true
	}
	return false
}

func (p *windowsProvider) GenerateKey(_ context.Context, keyID string) (crypto.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	hProv, err := openNCryptProvider()
	if err != nil {
		return nil, fmt.Errorf("tpm: open CNG provider: %w", err)
	}
	defer freeNCryptObject(hProv)

	// Try to open the existing key first (idempotent).
	hKey, err := openNCryptKey(hProv, keyID)
	if err == nil {
		defer freeNCryptObject(hKey)
		return p.signerFromHandle(hKey, keyID)
	}

	// Create a new TPM-backed machine-scoped EC key.
	keyName, _ := syscall.UTF16PtrFromString(keyID)
	algID, _ := syscall.UTF16PtrFromString("ECDSA_P256")

	var hNewKey uintptr
	ret, _, _ := procNCryptCreatePersistedKey.Call(
		hProv,
		uintptr(unsafe.Pointer(&hNewKey)),
		uintptr(unsafe.Pointer(algID)),
		uintptr(unsafe.Pointer(keyName)),
		0,
		ncryptMachinekeyFlag,
	)
	if ret != ncryptSuccess {
		return nil, fmt.Errorf("tpm: NCryptCreatePersistedKey: 0x%08X", ret)
	}
	defer freeNCryptObject(hNewKey)

	if err := finalizeNCryptKey(hNewKey); err != nil {
		return nil, fmt.Errorf("tpm: finalize key: %w", err)
	}

	return p.signerFromHandle(hNewKey, keyID)
}

func (p *windowsProvider) LoadKey(_ context.Context, keyID string) (crypto.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	hProv, err := openNCryptProvider()
	if err != nil {
		return nil, fmt.Errorf("tpm: open CNG provider: %w", err)
	}
	defer freeNCryptObject(hProv)

	hKey, err := openNCryptKey(hProv, keyID)
	if err != nil {
		return nil, ErrKeyNotFound
	}
	defer freeNCryptObject(hKey)

	return p.signerFromHandle(hKey, keyID)
}

func (p *windowsProvider) StoreCert(_ context.Context, keyID string, cert *x509.Certificate) error {
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

func (p *windowsProvider) LoadCert(_ context.Context, keyID string) (*x509.Certificate, error) {
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

// AttestationProof returns the EK certificate from TPM NV storage via TBS API.
// Full TPM2_Certify attestation is implemented in Phase 5.
func (p *windowsProvider) AttestationProof(_ context.Context, _ string) (*AttestationProof, error) {
	// On Windows, EK cert retrieval goes through TBS (TPM Base Services).
	// This is a Phase 5 concern; return a minimal proof that signals the intent.
	return nil, ErrAttestationNotSupported
}

// ActivateCredential is not yet supported on Windows. TPM2_ActivateCredential via
// CNG/TBS will be implemented in a follow-up task.
func (p *windowsProvider) ActivateCredential(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("tpm: ActivateCredential not yet supported on Windows; CNG/TBS implementation pending")
}

func (p *windowsProvider) certPath(keyID string) string {
	return filepath.Join(p.stateDir, "device-"+keyID+".crt")
}

// windowsSigner implements crypto.Signer via NCryptSignHash.
type windowsSigner struct {
	provider *windowsProvider
	pub      *ecdsa.PublicKey
	keyID    string
}

func (s *windowsSigner) Public() crypto.PublicKey { return s.pub }

func (s *windowsSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("tpm: cannot sign empty digest")
	}
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	hProv, err := openNCryptProvider()
	if err != nil {
		return nil, fmt.Errorf("tpm: open CNG provider for sign: %w", err)
	}
	defer freeNCryptObject(hProv)

	hKey, err := openNCryptKey(hProv, s.keyID)
	if err != nil {
		return nil, fmt.Errorf("tpm: open key for sign: %w", err)
	}
	defer freeNCryptObject(hKey)

	// NCryptSignHash produces a raw 64-byte IEEE P1363 signature (r||s).
	var sigLen uint32
	ret, _, _ := procNCryptSignHash.Call(
		hKey, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&sigLen)),
		0,
	)
	if ret != ncryptSuccess {
		return nil, fmt.Errorf("tpm: NCryptSignHash (get size): 0x%08X", ret)
	}

	sigBuf := make([]byte, sigLen)
	ret, _, _ = procNCryptSignHash.Call(
		hKey, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sigBuf[0])), uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		0,
	)
	if ret != ncryptSuccess {
		return nil, fmt.Errorf("tpm: NCryptSignHash: 0x%08X", ret)
	}

	// Convert P1363 (r||s) to DER-encoded ASN.1.
	half := len(sigBuf) / 2
	r := new(big.Int).SetBytes(sigBuf[:half])
	sigS := new(big.Int).SetBytes(sigBuf[half:])
	return asn1.Marshal(struct{ R, S *big.Int }{r, sigS})
}

// signerFromHandle reads the EC public key from an open NCrypt key handle.
func (p *windowsProvider) signerFromHandle(hKey uintptr, keyID string) (*windowsSigner, error) {
	// Export ECCPUBLICBLOB to get the X,Y coordinates.
	blobType, _ := syscall.UTF16PtrFromString("ECCPUBLICBLOB")
	var blobLen uint32
	ret, _, _ := procNCryptExportKey.Call(
		hKey, 0,
		uintptr(unsafe.Pointer(blobType)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if ret != ncryptSuccess {
		return nil, fmt.Errorf("tpm: NCryptExportKey (get size): 0x%08X", ret)
	}

	blob := make([]byte, blobLen)
	ret, _, _ = procNCryptExportKey.Call(
		hKey, 0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(blobLen),
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if ret != ncryptSuccess {
		return nil, fmt.Errorf("tpm: NCryptExportKey: 0x%08X", ret)
	}

	ecPub, err := ecPublicFromECCPublicBLOB(blob)
	if err != nil {
		return nil, err
	}
	return &windowsSigner{provider: p, pub: ecPub, keyID: keyID}, nil
}

// openNCryptProvider opens the TPM-backed CNG storage provider.
func openNCryptProvider() (uintptr, error) {
	var hProv uintptr
	providerName, _ := syscall.UTF16PtrFromString(ncryptProviderName)
	ret, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProv)),
		uintptr(unsafe.Pointer(providerName)),
		0,
	)
	if ret != ncryptSuccess {
		return 0, fmt.Errorf("NCryptOpenStorageProvider: 0x%08X", ret)
	}
	return hProv, nil
}

// openNCryptKey opens an existing machine-scoped CNG key by name.
func openNCryptKey(hProv uintptr, keyID string) (uintptr, error) {
	var hKey uintptr
	keyName, _ := syscall.UTF16PtrFromString(keyID)
	ret, _, _ := procNCryptOpenKey.Call(
		hProv,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(keyName)),
		0,
		ncryptMachinekeyFlag,
	)
	if ret != ncryptSuccess {
		return 0, fmt.Errorf("NCryptOpenKey: 0x%08X", ret)
	}
	return hKey, nil
}

func finalizeNCryptKey(hKey uintptr) error {
	ret, _, _ := procNCryptFinalizeKey.Call(hKey, 0)
	if ret != ncryptSuccess {
		return fmt.Errorf("NCryptFinalizeKey: 0x%08X", ret)
	}
	return nil
}

func freeNCryptObject(h uintptr) {
	_, _, _ = procNCryptFreeObject.Call(h)
}

// BCRYPT_ECCPUBLICBLOB layout (CNG):
//
//	[0..3]   magic  (BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345)
//	[4..7]   cbKey  (32 for P-256; little-endian uint32)
//	[8..8+cbKey-1]   X coordinate
//	[8+cbKey..8+2*cbKey-1]  Y coordinate
const bCryptECDSAPublicP256Magic = uint32(0x31534345)

func ecPublicFromECCPublicBLOB(blob []byte) (*ecdsa.PublicKey, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("tpm: ECCPUBLICBLOB too short (%d bytes)", len(blob))
	}

	// Validate magic to ensure this is an ECDSA P-256 blob.
	magic := uint32(blob[0]) | uint32(blob[1])<<8 | uint32(blob[2])<<16 | uint32(blob[3])<<24
	if magic != bCryptECDSAPublicP256Magic {
		return nil, fmt.Errorf("tpm: ECCPUBLICBLOB has unexpected magic 0x%08X (expected 0x%08X)", magic, bCryptECDSAPublicP256Magic)
	}

	// cbKey must be exactly 32 for P-256 to avoid integer overflow in slice bounds below.
	cbKey := int(blob[4]) | int(blob[5])<<8 | int(blob[6])<<16 | int(blob[7])<<24
	if cbKey != 32 {
		return nil, fmt.Errorf("tpm: ECCPUBLICBLOB has unexpected cbKey=%d (expected 32 for P-256)", cbKey)
	}

	const totalLen = 8 + 2*32 // header + X + Y
	if len(blob) < totalLen {
		return nil, fmt.Errorf("tpm: ECCPUBLICBLOB too short for P-256 (%d < %d)", len(blob), totalLen)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(blob[8 : 8+cbKey]),
		Y:     new(big.Int).SetBytes(blob[8+cbKey : 8+2*cbKey]),
	}, nil
}

