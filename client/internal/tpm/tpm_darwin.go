//go:build darwin

package tpm

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <stdbool.h>

// nbIsNullSecKey checks whether a SecKeyRef is NULL.
// CGo maps CF bridged types (CF_BRIDGED_TYPE) to struct wrappers that cannot be
// compared directly to nil in Go; a typed C-level null check avoids unsafe.Pointer casts.
static bool nbIsNullSecKey(SecKeyRef p)   { return p == NULL; }

// nbIsNullCFError checks whether a CFErrorRef is NULL.
static bool nbIsNullCFError(CFErrorRef p) { return p == NULL; }

// nbProbeSecureEnclave attempts to create an ephemeral, non-permanent Secure Enclave
// key to verify SE is present and accessible. Returns true if SE is available.
bool nbProbeSecureEnclave(void) {
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!params) return false;

    int bits = 256;
    CFNumberRef bitsNum = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    if (!bitsNum) { CFRelease(params); return false; }

    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, bitsNum);
    CFRelease(bitsNum);
    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    // kSecAttrIsPermanent=false: ephemeral key, not stored in Keychain.
    CFDictionarySetValue(params, kSecAttrIsPermanent, kCFBooleanFalse);

    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(params, &err);
    CFRelease(params);
    if (err) CFRelease(err);

    if (key) {
        CFRelease(key);
        return true;
    }
    return false;
}

// nbCreateSEKey creates a non-exportable EC P-256 key in the Secure Enclave.
// Returns the SecKeyRef (caller must CFRelease) or NULL on failure.
SecKeyRef nbCreateSEKey(const char* label, CFErrorRef* outError) {
    CFStringRef labelStr = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    if (!labelStr) return NULL;

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!params) { CFRelease(labelStr); return NULL; }

    int bits = 256;
    CFNumberRef bitsNum = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    if (!bitsNum) { CFRelease(params); CFRelease(labelStr); return NULL; }

    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, bitsNum);
    CFRelease(bitsNum); // dict retains its own reference

    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(params, kSecAttrLabel, labelStr);
    CFDictionarySetValue(params, kSecAttrIsPermanent, kCFBooleanTrue);

    // Access control: private key usage, accessible after first unlock, this device only.
    // kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly (vs WhenUnlocked) allows the
    // NetBird daemon to use the key when the screen is locked — necessary for background
    // VPN reconnection after reboot. The key is still non-exportable and device-bound
    // (non-migratable across backups or iCloud Keychain).
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        NULL,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        outError);
    if (!acl) {
        CFRelease(params);
        CFRelease(labelStr);
        return NULL;
    }
    CFDictionarySetValue(params, kSecAttrAccessControl, acl);
    CFRelease(acl);

    SecKeyRef privateKey = SecKeyCreateRandomKey(params, outError);
    CFRelease(params);
    CFRelease(labelStr);
    return privateKey;
}

// nbLoadSEKey loads an existing Secure Enclave key by label from the Keychain.
// Returns NULL if the key does not exist. Caller must CFRelease the result.
SecKeyRef nbLoadSEKey(const char* label) {
    CFStringRef labelStr = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    if (!labelStr) return NULL;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!query) { CFRelease(labelStr); return NULL; }

    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(query, kSecAttrLabel, labelStr);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);

    CFTypeRef result = NULL;
    SecItemCopyMatching(query, &result);

    CFRelease(query);
    CFRelease(labelStr);
    return (SecKeyRef)result;
}

// nbGetPublicKeyBytes exports the EC public key as an uncompressed point (04 || X || Y).
// Returns NULL on failure. Caller must free() the returned buffer.
unsigned char* nbGetPublicKeyBytes(SecKeyRef privateKey, size_t* outLen, CFErrorRef* outError) {
    SecKeyRef pubKey = SecKeyCopyPublicKey(privateKey);
    if (!pubKey) return NULL;

    CFDataRef data = SecKeyCopyExternalRepresentation(pubKey, outError);
    CFRelease(pubKey);
    if (!data) return NULL;

    size_t len = CFDataGetLength(data);
    unsigned char* buf = (unsigned char*)malloc(len);
    if (buf) {
        memcpy(buf, CFDataGetBytePtr(data), len);
        *outLen = len;
    }
    CFRelease(data);
    return buf;
}

// nbSignDigest signs a SHA-256 digest using the Secure Enclave key and returns a
// DER-encoded ECDSA signature (kSecKeyAlgorithmECDSASignatureDigestX962SHA256).
// Returns NULL on failure. Caller must free() the returned buffer.
unsigned char* nbSignDigest(SecKeyRef privateKey, const unsigned char* digest, size_t digestLen,
                            size_t* outSigLen, CFErrorRef* outError) {
    CFDataRef digestData = CFDataCreate(NULL, digest, (CFIndex)digestLen);
    if (!digestData) return NULL;

    CFDataRef sig = SecKeyCreateSignature(
        privateKey,
        kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
        digestData,
        outError);
    CFRelease(digestData);

    if (!sig) return NULL;

    size_t len = CFDataGetLength(sig);
    unsigned char* buf = (unsigned char*)malloc(len);
    if (buf) {
        memcpy(buf, CFDataGetBytePtr(sig), len);
        *outSigLen = len;
    }
    CFRelease(sig);
    return buf;
}

// nbCFErrorString returns a malloc'd UTF-8 string describing the CFError.
// Returns NULL if cfErr is NULL. Caller must free() the result.
char* nbCFErrorString(CFErrorRef cfErr) {
    if (!cfErr) return NULL;
    CFStringRef desc = CFErrorCopyDescription(cfErr);
    if (!desc) return NULL;

    char* buf = (char*)malloc(512);
    if (buf) {
        if (!CFStringGetCString(desc, buf, 512, kCFStringEncodingUTF8)) {
            buf[0] = '\0';
        }
    }
    CFRelease(desc);
    return buf;
}

// SecKeyCreateAttestation is available in the Security framework on macOS 10.14+ but
// is not declared in the public SDK headers. Forward-declare it so we can link against
// the runtime symbol without importing a private header.
CFDataRef SecKeyCreateAttestation(SecKeyRef key, SecKeyRef CA, CFErrorRef *error)
    __attribute__((availability(macos, introduced=10.14)));

// nbCreateSEAttestation calls SecKeyCreateAttestation(key, NULL, &err) to obtain a
// DER-encoded attestation leaf certificate proving that `key` resides in the Secure Enclave.
// Passing NULL as the CA key causes the OS to use Apple's built-in attestation chain.
// Returns a malloc'd buffer containing the DER bytes. Caller must free() it.
// Returns NULL and sets *outLen=0 on failure.
unsigned char* nbCreateSEAttestation(SecKeyRef key, size_t* outLen, CFErrorRef* outError) {
    *outLen = 0;
    CFDataRef attestData = SecKeyCreateAttestation(key, NULL, outError);
    if (!attestData) return NULL;

    size_t len = CFDataGetLength(attestData);
    unsigned char* buf = (unsigned char*)malloc(len);
    if (buf) {
        memcpy(buf, CFDataGetBytePtr(attestData), len);
        *outLen = len;
    }
    CFRelease(attestData);
    return buf;
}
*/
import "C"
import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"unsafe"
)

const keychainLabelPrefix = "netbird-device-key"

// darwinProvider implements Provider using the macOS Secure Enclave via Security.framework (CGo).
// Private keys reside in the SE and are never exported; kSecAttrTokenIDSecureEnclave
// ensures all cryptographic operations happen inside the hardware.
// Certificates are stored as PEM files in stateDir (public data — no SE required).
type darwinProvider struct {
	mu       sync.Mutex
	stateDir string
}

// NewPlatformProvider returns a Secure Enclave-backed Provider on macOS.
// If no stateDir is supplied, /var/lib/netbird is used.
func NewPlatformProvider(stateDir ...string) Provider {
	dir := "/var/lib/netbird"
	if len(stateDir) > 0 && stateDir[0] != "" {
		dir = stateDir[0]
	}
	return &darwinProvider{stateDir: dir}
}

// Available returns true only when the Secure Enclave is present and accessible.
// It probes by attempting to create an ephemeral (non-permanent) SE key;
// this is the only reliable way to detect SE without hardware-specific sysctls.
// Pre-2018 Intel Macs and all VM environments will return false.
func (p *darwinProvider) Available() bool {
	return bool(C.nbProbeSecureEnclave())
}

// GenerateKey creates or returns an EC P-256 key in the Secure Enclave.
// The key is stored in the system Keychain with label keychainLabelPrefix+"-"+keyID.
func (p *darwinProvider) GenerateKey(_ context.Context, keyID string) (crypto.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	label := keychainLabel(keyID)

	// Try to load an existing key first (idempotent).
	if signer, err := p.loadKeyByLabel(label); err == nil {
		return signer, nil
	}

	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	var cfErr C.CFErrorRef
	keyRef := C.nbCreateSEKey(cLabel, &cfErr) //nolint:gocritic // CGo: gocritic incorrectly flags &cfErr as dupSubExpr
	if C.nbIsNullSecKey(keyRef) {
		errMsg := cferrorString(cfErr)
		if !C.nbIsNullCFError(cfErr) {
			C.CFRelease(C.CFTypeRef(cfErr))
		}
		return nil, fmt.Errorf("tpm: SecKeyCreateRandomKey: %s", errMsg)
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	ecPub, err := publicKeyFromSERef(keyRef)
	if err != nil {
		return nil, err
	}
	return &darwinSigner{provider: p, pub: ecPub, label: label}, nil
}

func (p *darwinProvider) LoadKey(_ context.Context, keyID string) (crypto.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	signer, err := p.loadKeyByLabel(keychainLabel(keyID))
	if err != nil {
		return nil, ErrKeyNotFound
	}
	return signer, nil
}

// loadKeyByLabel loads a Secure Enclave key from the Keychain by its label.
// Must be called with p.mu held.
func (p *darwinProvider) loadKeyByLabel(label string) (*darwinSigner, error) {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	keyRef := C.nbLoadSEKey(cLabel)
	if C.nbIsNullSecKey(keyRef) {
		return nil, ErrKeyNotFound
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	ecPub, err := publicKeyFromSERef(keyRef)
	if err != nil {
		return nil, err
	}
	return &darwinSigner{provider: p, pub: ecPub, label: label}, nil
}

func (p *darwinProvider) StoreCert(_ context.Context, keyID string, cert *x509.Certificate) error {
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
	// Write PEM-encoded certificate — public data only, no private key.
	return writePEMCert(f, cert.Raw)
}

func (p *darwinProvider) LoadCert(_ context.Context, keyID string) (*x509.Certificate, error) {
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
	return parsePEMCert(data)
}

// AttestationProof returns ErrAttestationNotSupported on macOS.
// Apple Secure Enclave does not expose an Endorsement Key or TPM2_Certify equivalent.
// Device attestation on Apple platforms requires Apple DeviceCheck/App Attest APIs
// which are out of scope for this feature (Phase 5 note in spec).
func (p *darwinProvider) AttestationProof(_ context.Context, _ string) (*AttestationProof, error) {
	return nil, ErrAttestationNotSupported
}

// ActivateCredential is not supported on macOS. Apple Secure Enclave has no
// TPM2_ActivateCredential equivalent; use AttestAppleSE instead.
func (p *darwinProvider) ActivateCredential(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("tpm: ActivateCredential not supported on Apple SE; use AttestAppleSE")
}

// CreateSEAttestation calls Apple's SecKeyCreateAttestation for the key identified by keyID,
// returning a single-element slice containing the DER-encoded attestation certificate.
// The OS provides its own CA chain, so only the leaf is returned here; callers must append
// Apple's intermediate and root to form a complete chain for verification.
//
// Requires: macOS 10.14+, Keychain entitlements, Apple chip or T2 security chip.
// Returns a descriptive error on Intel Macs without a T2 chip.
func (p *darwinProvider) CreateSEAttestation(_ context.Context, keyID string) ([][]byte, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	cLabel := C.CString(keychainLabel(keyID))
	defer C.free(unsafe.Pointer(cLabel))

	keyRef := C.nbLoadSEKey(cLabel)
	if C.nbIsNullSecKey(keyRef) {
		return nil, fmt.Errorf("tpm: CreateSEAttestation: key %q not found in Keychain", keyID)
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	var cfErr C.CFErrorRef
	var attestLen C.size_t
	attestPtr := C.nbCreateSEAttestation(keyRef, &attestLen, &cfErr) //nolint:gocritic
	if attestPtr == nil {
		errMsg := cferrorString(cfErr)
		if !C.nbIsNullCFError(cfErr) {
			C.CFRelease(C.CFTypeRef(cfErr))
		}
		return nil, fmt.Errorf("tpm: SecKeyCreateAttestation: %s", errMsg)
	}
	defer C.free(unsafe.Pointer(attestPtr))

	// attestLen is C.size_t (uint64 on arm64). Guard against implausible size before
	// casting to C.int for C.GoBytes (which takes a signed 32-bit length).
	if attestLen > 1<<20 {
		return nil, fmt.Errorf("tpm: attestation buffer implausibly large (%d bytes)", attestLen)
	}
	der := C.GoBytes(unsafe.Pointer(attestPtr), C.int(attestLen))
	return [][]byte{der}, nil
}

func (p *darwinProvider) certPath(keyID string) string {
	return filepath.Join(p.stateDir, "device-"+keyID+".crt")
}

func keychainLabel(keyID string) string {
	return keychainLabelPrefix + "-" + keyID
}

// darwinSigner is a crypto.Signer backed by a Secure Enclave key.
// Each Sign call opens the Keychain key and delegates to SecKeyCreateSignature.
type darwinSigner struct {
	provider *darwinProvider
	pub      *ecdsa.PublicKey
	label    string
}

func (s *darwinSigner) Public() crypto.PublicKey { return s.pub }

func (s *darwinSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("tpm: cannot sign empty digest")
	}

	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	cLabel := C.CString(s.label)
	defer C.free(unsafe.Pointer(cLabel))

	keyRef := C.nbLoadSEKey(cLabel)
	if C.nbIsNullSecKey(keyRef) {
		return nil, fmt.Errorf("tpm: key not found in Keychain during sign: %s", s.label)
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	var cfErr C.CFErrorRef
	var sigLen C.size_t
	sigPtr := C.nbSignDigest(keyRef,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		&sigLen,
		&cfErr) //nolint:gocritic // CGo: gocritic incorrectly flags &cfErr as dupSubExpr
	if sigPtr == nil {
		errMsg := cferrorString(cfErr)
		if !C.nbIsNullCFError(cfErr) {
			C.CFRelease(C.CFTypeRef(cfErr))
		}
		return nil, fmt.Errorf("tpm: SecKeyCreateSignature: %s", errMsg)
	}
	defer C.free(unsafe.Pointer(sigPtr))

	// nbSignDigest returns DER-encoded ECDSA (kSecKeyAlgorithmECDSASignatureDigestX962SHA256).
	return C.GoBytes(unsafe.Pointer(sigPtr), C.int(sigLen)), nil
}

// publicKeyFromSERef extracts an *ecdsa.PublicKey from a SecKeyRef.
func publicKeyFromSERef(keyRef C.SecKeyRef) (*ecdsa.PublicKey, error) {
	var cfErr C.CFErrorRef
	var pubLen C.size_t
	pubPtr := C.nbGetPublicKeyBytes(keyRef, &pubLen, &cfErr) //nolint:gocritic // CGo: gocritic incorrectly flags &cfErr as dupSubExpr
	if pubPtr == nil {
		errMsg := cferrorString(cfErr)
		if !C.nbIsNullCFError(cfErr) {
			C.CFRelease(C.CFTypeRef(cfErr))
		}
		return nil, fmt.Errorf("tpm: SecKeyCopyExternalRepresentation: %s", errMsg)
	}
	defer C.free(unsafe.Pointer(pubPtr))

	// Uncompressed point: 0x04 || 32-byte X || 32-byte Y (total 65 bytes for P-256).
	raw := C.GoBytes(unsafe.Pointer(pubPtr), C.int(pubLen))
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("tpm: unexpected public key format (len=%d prefix=0x%02x)", len(raw), raw[0])
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}, nil
}

// cferrorString returns the description of a CFErrorRef as a Go string.
// Uses a C-level helper to avoid unsafe.Pointer games with CF types.
func cferrorString(cfErr C.CFErrorRef) string {
	if C.nbIsNullCFError(cfErr) {
		return "unknown error"
	}
	cStr := C.nbCFErrorString(cfErr)
	if cStr == nil {
		return "unknown error"
	}
	defer C.free(unsafe.Pointer(cStr))
	return C.GoString(cStr)
}
