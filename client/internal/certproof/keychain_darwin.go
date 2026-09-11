package certproof

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

const (
	securityFramework       = "/System/Library/Frameworks/Security.framework/Security"
	coreFoundationFramework = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

	errSecItemNotFound = -25300
)

var (
	keychainOnce sync.Once
	keychainErr  error

	secItemCopyMatching        func(query uintptr, result *uintptr) int32
	secIdentityCopyCertificate func(identity uintptr, cert *uintptr) int32
	secIdentityCopyPrivateKey  func(identity uintptr, key *uintptr) int32
	secCertificateCopyData     func(cert uintptr) uintptr
	secKeyCreateSignature      func(key, algorithm, data uintptr, err *uintptr) uintptr

	cfDictionaryCreate     func(alloc uintptr, keys, values *uintptr, count int, keyCallBacks, valueCallBacks uintptr) uintptr
	cfArrayGetCount        func(array uintptr) int
	cfArrayGetValueAtIndex func(array uintptr, index int) uintptr
	cfDataCreate           func(alloc uintptr, data *byte, length int) uintptr
	cfDataGetLength        func(data uintptr) int
	cfDataGetBytePtr       func(data uintptr) unsafe.Pointer
	cfErrorGetCode         func(err uintptr) int
	cfRelease              func(ref uintptr)

	kSecClass, kSecClassIdentity, kSecClassCertificate, kSecMatchLimit, kSecMatchLimitAll, kSecReturnRef uintptr
	kSecKeyAlgorithmECDSASHA256, kSecKeyAlgorithmECDSASHA384, kSecKeyAlgorithmRSAPSSSHA256               uintptr
	kCFBooleanTrue, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks                       uintptr
)

// DefaultStore is the keychain search list of the daemon, which for the root daemon is
// the System keychain where MDM installs device identities.
func DefaultStore() Store {
	return NewKeychainStore()
}

// KeychainStore yields the identities of the process's keychain search list, reached
// through purego so the client keeps building with CGO_ENABLED=0.
type KeychainStore struct{}

func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

func (s *KeychainStore) Candidates(_ context.Context) ([]Candidate, error) {
	if err := loadKeychain(); err != nil {
		return nil, err
	}
	var leaves []*x509.Certificate
	err := eachIdentity(func(_ uintptr, der []byte) (bool, error) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			log.Warnf("skipping keychain identity: %v", err)
			return false, nil
		}
		leaves = append(leaves, cert)
		return false, nil
	})
	if err != nil || len(leaves) == 0 {
		return nil, err
	}
	pool, err := keychainCertificates()
	if err != nil {
		return nil, err
	}
	candidates := make([]Candidate, 0, len(leaves))
	for _, leaf := range leaves {
		candidates = append(candidates, Candidate{Chain: buildChain(leaf, pool), Signer: &keychainSigner{leaf: leaf}})
	}
	return candidates, nil
}

// keychainSigner holds only the certificate; the identity is looked up again at signing
// time so no keychain references outlive a call.
type keychainSigner struct {
	leaf *x509.Certificate
}

func (s *keychainSigner) Public() crypto.PublicKey {
	return s.leaf.PublicKey
}

func (s *keychainSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	scheme, err := schemeFor(s.leaf.PublicKey, opts)
	if err != nil {
		return nil, err
	}
	algorithm := keychainAlgorithm(scheme)
	var signature []byte
	err = eachIdentity(func(identity uintptr, der []byte) (bool, error) {
		if !bytes.Equal(der, s.leaf.Raw) {
			return false, nil
		}
		signature, err = signWithIdentity(identity, algorithm, digest)
		return true, err
	})
	if err != nil {
		return nil, err
	}
	if signature == nil {
		return nil, errors.New("certificate is no longer in the keychain")
	}
	return signature, nil
}

func keychainAlgorithm(scheme sigScheme) uintptr {
	switch scheme {
	case schemeECDSASHA384:
		return kSecKeyAlgorithmECDSASHA384
	case schemeRSAPSSSHA256:
		return kSecKeyAlgorithmRSAPSSSHA256
	default:
		return kSecKeyAlgorithmECDSASHA256
	}
}

func signWithIdentity(identity, algorithm uintptr, digest []byte) ([]byte, error) {
	var key uintptr
	if status := secIdentityCopyPrivateKey(identity, &key); status != 0 {
		return nil, fmt.Errorf("SecIdentityCopyPrivateKey: %d", status)
	}
	defer cfRelease(key)

	data := cfDataCreate(0, &digest[0], len(digest))
	defer cfRelease(data)

	var cfErr uintptr
	signature := secKeyCreateSignature(key, algorithm, data, &cfErr)
	if signature == 0 {
		defer cfRelease(cfErr)
		return nil, fmt.Errorf("SecKeyCreateSignature: CFError %d", cfErrorGetCode(cfErr))
	}
	defer cfRelease(signature)
	return dataBytes(signature), nil
}

func eachIdentity(fn func(identity uintptr, der []byte) (bool, error)) error {
	return eachMatching(kSecClassIdentity, func(identity uintptr) (bool, error) {
		var cert uintptr
		if status := secIdentityCopyCertificate(identity, &cert); status != 0 {
			return true, fmt.Errorf("SecIdentityCopyCertificate: %d", status)
		}
		der := certificateDER(cert)
		cfRelease(cert)
		return fn(identity, der)
	})
}

func keychainCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	err := eachMatching(kSecClassCertificate, func(item uintptr) (bool, error) {
		if cert, err := x509.ParseCertificate(certificateDER(item)); err == nil {
			certs = append(certs, cert)
		}
		return false, nil
	})
	return certs, err
}

func eachMatching(class uintptr, fn func(item uintptr) (bool, error)) error {
	keys := []uintptr{kSecClass, kSecMatchLimit, kSecReturnRef}
	values := []uintptr{class, kSecMatchLimitAll, kCFBooleanTrue}
	query := cfDictionaryCreate(0, &keys[0], &values[0], len(keys), kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)
	defer cfRelease(query)

	var items uintptr
	switch status := secItemCopyMatching(query, &items); status {
	case 0:
	case errSecItemNotFound:
		return nil
	default:
		return fmt.Errorf("SecItemCopyMatching: %d", status)
	}
	defer cfRelease(items)
	for i, n := 0, cfArrayGetCount(items); i < n; i++ {
		if stop, err := fn(cfArrayGetValueAtIndex(items, i)); stop || err != nil {
			return err
		}
	}
	return nil
}

func certificateDER(cert uintptr) []byte {
	data := secCertificateCopyData(cert)
	defer cfRelease(data)
	return dataBytes(data)
}

func dataBytes(data uintptr) []byte {
	return bytes.Clone(unsafe.Slice((*byte)(cfDataGetBytePtr(data)), cfDataGetLength(data)))
}

func loadKeychain() error {
	keychainOnce.Do(func() { keychainErr = resolveKeychain() })
	return keychainErr
}

func resolveKeychain() error {
	security, err := purego.Dlopen(securityFramework, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("open %s: %w", securityFramework, err)
	}
	coreFoundation, err := purego.Dlopen(coreFoundationFramework, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("open %s: %w", coreFoundationFramework, err)
	}

	for _, fn := range []struct {
		ptr  any
		lib  uintptr
		name string
	}{
		{&secItemCopyMatching, security, "SecItemCopyMatching"},
		{&secIdentityCopyCertificate, security, "SecIdentityCopyCertificate"},
		{&secIdentityCopyPrivateKey, security, "SecIdentityCopyPrivateKey"},
		{&secCertificateCopyData, security, "SecCertificateCopyData"},
		{&secKeyCreateSignature, security, "SecKeyCreateSignature"},
		{&cfDictionaryCreate, coreFoundation, "CFDictionaryCreate"},
		{&cfArrayGetCount, coreFoundation, "CFArrayGetCount"},
		{&cfArrayGetValueAtIndex, coreFoundation, "CFArrayGetValueAtIndex"},
		{&cfDataCreate, coreFoundation, "CFDataCreate"},
		{&cfDataGetLength, coreFoundation, "CFDataGetLength"},
		{&cfDataGetBytePtr, coreFoundation, "CFDataGetBytePtr"},
		{&cfErrorGetCode, coreFoundation, "CFErrorGetCode"},
		{&cfRelease, coreFoundation, "CFRelease"},
	} {
		symbol, err := purego.Dlsym(fn.lib, fn.name)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", fn.name, err)
		}
		purego.RegisterFunc(fn.ptr, symbol)
	}

	for _, global := range []struct {
		ptr   *uintptr
		lib   uintptr
		name  string
		deref bool
	}{
		{&kSecClass, security, "kSecClass", true},
		{&kSecClassIdentity, security, "kSecClassIdentity", true},
		{&kSecClassCertificate, security, "kSecClassCertificate", true},
		{&kSecMatchLimit, security, "kSecMatchLimit", true},
		{&kSecMatchLimitAll, security, "kSecMatchLimitAll", true},
		{&kSecReturnRef, security, "kSecReturnRef", true},
		{&kSecKeyAlgorithmECDSASHA256, security, "kSecKeyAlgorithmECDSASignatureDigestX962SHA256", true},
		{&kSecKeyAlgorithmECDSASHA384, security, "kSecKeyAlgorithmECDSASignatureDigestX962SHA384", true},
		{&kSecKeyAlgorithmRSAPSSSHA256, security, "kSecKeyAlgorithmRSASignatureDigestPSSSHA256", true},
		{&kCFBooleanTrue, coreFoundation, "kCFBooleanTrue", true},
		{&kCFTypeDictionaryKeyCallBacks, coreFoundation, "kCFTypeDictionaryKeyCallBacks", false},
		{&kCFTypeDictionaryValueCallBacks, coreFoundation, "kCFTypeDictionaryValueCallBacks", false},
	} {
		addr, err := purego.Dlsym(global.lib, global.name)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", global.name, err)
		}
		if global.deref {
			addr = **(**uintptr)(unsafe.Pointer(&addr))
		}
		*global.ptr = addr
	}
	return nil
}
