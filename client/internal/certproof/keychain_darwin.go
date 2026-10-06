//go:build !ios

package certproof

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

const (
	securityFramework       = "/System/Library/Frameworks/Security.framework/Security"
	coreFoundationFramework = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

	errSecItemNotFound          = -25300
	errSecInteractionNotAllowed = -25308
)

// errKeyNeedsApproval reports a key whose access list does not include netbird, so using
// it needs the user's approval, which a daemon has no UI to ask for.
var errKeyNeedsApproval = errors.New("the key's access control requires user approval for netbird; " +
	"import the identity with netbird allowed (security import -T /path/to/netbird), " +
	"or set AllowAllAppsAccess in the MDM certificate payload")

var (
	keychainOnce sync.Once
	keychainErr  error

	secItemCopyMatching        func(query uintptr, result *uintptr) int32
	secIdentityCopyCertificate func(identity uintptr, cert *uintptr) int32
	secIdentityCopyPrivateKey  func(identity uintptr, key *uintptr) int32
	secCertificateCopyData     func(cert uintptr) uintptr
	secKeyCreateSignature      func(key, algorithm, data uintptr, err *uintptr) uintptr

	secKeychainCopySearchList func(searchList *uintptr) int32
	secKeychainGetPath        func(keychain uintptr, pathLength *uint32, path *byte) int32

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
		log.Debugf("keychain identity: subject=%q issuer=%q serial=%s expires=%s", cert.Subject, cert.Issuer, cert.SerialNumber, cert.NotAfter)
		leaves = append(leaves, cert)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	// The certificate query runs even without identities: it separates a keychain that is
	// readable but holds no identity from one the process cannot read at all.
	pool, err := keychainCertificates()
	if err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		log.Debugf("keychain search list holds no identities usable for certificate posture, but %d readable certificates: an identity needs its private key in the same keychain", len(pool))
		return nil, nil
	}
	log.Debugf("keychain search list holds %d identities and %d certificates for chain building", len(leaves), len(pool))

	candidates := make([]Candidate, 0, len(leaves))
	for _, leaf := range leaves {
		chain := buildChain(leaf, pool)
		log.Debugf("keychain candidate %q issued by %q built a chain of %d certificates", leaf.Subject, leaf.Issuer, len(chain))
		if len(chain) == 1 && leaf.CheckSignatureFrom(leaf) != nil {
			log.Debugf("keychain candidate %q has no issuer in the keychain, its proof carries the leaf alone and only verifies if the challenge supplies %q", leaf.Subject, leaf.Issuer)
		}
		candidates = append(candidates, Candidate{Chain: chain, Signer: &keychainSigner{leaf: leaf}, Intermediates: pool})
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
	log.Debugf("signing certificate posture challenge with keychain key of %q", s.leaf.Subject)

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
	log.Debugf("keychain signed certificate posture challenge for %q, %d bytes", s.leaf.Subject, len(signature))
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
	defer release(key)

	data := cfDataCreate(0, &digest[0], len(digest))
	if data == 0 {
		return nil, errors.New("CFDataCreate returned NULL")
	}
	defer release(data)

	var cfErr uintptr
	signature := secKeyCreateSignature(key, algorithm, data, &cfErr)
	if signature == 0 {
		if cfErr == 0 {
			return nil, errors.New("SecKeyCreateSignature failed without a CFError")
		}
		defer release(cfErr)
		code := cfErrorGetCode(cfErr)
		if code == errSecInteractionNotAllowed {
			return nil, fmt.Errorf("SecKeyCreateSignature: CFError %d: %w", code, errKeyNeedsApproval)
		}
		return nil, fmt.Errorf("SecKeyCreateSignature: CFError %d", code)
	}
	defer release(signature)
	return dataBytes(signature), nil
}

// eachIdentity calls fn with every identity in the search list and its certificate. An
// identity whose certificate cannot be read is skipped rather than ending the walk.
func eachIdentity(fn func(identity uintptr, der []byte) (bool, error)) error {
	return eachMatching(kSecClassIdentity, "identity", func(identity uintptr) (bool, error) {
		var cert uintptr
		if status := secIdentityCopyCertificate(identity, &cert); status != 0 {
			log.Debugf("skipping keychain identity: SecIdentityCopyCertificate: %d", status)
			return false, nil
		}
		der := certificateDER(cert)
		release(cert)
		if der == nil {
			log.Debug("skipping keychain identity whose certificate has no DER data")
			return false, nil
		}
		return fn(identity, der)
	})
}

func keychainCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var unparsable int
	err := eachMatching(kSecClassCertificate, "certificate", func(item uintptr) (bool, error) {
		if cert, err := x509.ParseCertificate(certificateDER(item)); err == nil {
			certs = append(certs, cert)
			return false, nil
		}
		unparsable++
		return false, nil
	})
	log.Debugf("keychain holds %d parsable certificates, %d unparsable", len(certs), unparsable)
	return certs, err
}

func eachMatching(class uintptr, name string, fn func(item uintptr) (bool, error)) error {
	keys := []uintptr{kSecClass, kSecMatchLimit, kSecReturnRef}
	values := []uintptr{class, kSecMatchLimitAll, kCFBooleanTrue}
	query := cfDictionaryCreate(0, &keys[0], &values[0], len(keys), kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)
	defer release(query)

	var items uintptr
	switch status := secItemCopyMatching(query, &items); status {
	case 0:
	case errSecItemNotFound:
		log.Debugf("keychain %s query returned errSecItemNotFound (%d): the search list holds no item of this class", name, errSecItemNotFound)
		return nil
	default:
		log.Debugf("keychain %s query returned OSStatus %d", name, status)
		return fmt.Errorf("SecItemCopyMatching: %d", status)
	}
	defer release(items)

	n := cfArrayGetCount(items)
	log.Debugf("keychain %s query returned %d items", name, n)
	for i := 0; i < n; i++ {
		if stop, err := fn(cfArrayGetValueAtIndex(items, i)); stop || err != nil {
			return err
		}
	}
	return nil
}

// certificateDER returns the DER form of cert, or nil when SecCertificateCopyData
// returns NULL, which it does for an object that is not a valid certificate.
func certificateDER(cert uintptr) []byte {
	data := secCertificateCopyData(cert)
	if data == 0 {
		return nil
	}
	defer release(data)
	return dataBytes(data)
}

func dataBytes(data uintptr) []byte {
	n := cfDataGetLength(data)
	if n <= 0 {
		return nil
	}
	return bytes.Clone(unsafe.Slice((*byte)(cfDataGetBytePtr(data)), n))
}

// release drops a CoreFoundation reference. CFRelease crashes the process on NULL, and
// several Security calls return NULL on failure, so every release goes through here.
func release(ref uintptr) {
	if ref != 0 {
		cfRelease(ref)
	}
}

func loadKeychain() error {
	keychainOnce.Do(func() {
		if keychainErr = resolveKeychain(); keychainErr != nil {
			log.Debugf("macOS keychain unavailable for certificate posture: %v", keychainErr)
			return
		}
		log.Debugf("macOS Security framework loaded for certificate posture, running as uid=%d euid=%d", os.Getuid(), os.Geteuid())
		logSearchList()
	})
	return keychainErr
}

// logSearchList reports the keychains the process searches. The root daemon sees the
// System keychain and System Roots, never a user's login keychain.
func logSearchList() {
	if secKeychainCopySearchList == nil || secKeychainGetPath == nil {
		log.Debug("keychain search list diagnostics unavailable on this macOS version")
		return
	}

	var list uintptr
	if status := secKeychainCopySearchList(&list); status != 0 {
		log.Debugf("SecKeychainCopySearchList returned OSStatus %d", status)
		return
	}
	defer release(list)

	n := cfArrayGetCount(list)
	log.Debugf("keychain search list contains %d keychains", n)
	for i := 0; i < n; i++ {
		log.Debugf("keychain search list[%d]: %s", i, keychainPath(cfArrayGetValueAtIndex(list, i)))
	}
}

func keychainPath(keychain uintptr) string {
	path := make([]byte, 1024)
	length := uint32(len(path))
	if status := secKeychainGetPath(keychain, &length, &path[0]); status != 0 {
		return fmt.Sprintf("<SecKeychainGetPath: %d>", status)
	}
	return string(path[:length])
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

	resolveOptional(security, "SecKeychainCopySearchList", &secKeychainCopySearchList)
	resolveOptional(security, "SecKeychainGetPath", &secKeychainGetPath)
	return nil
}

// resolveOptional binds a diagnostic-only symbol, leaving it nil when the framework no
// longer exports it so keychain lookups keep working without it.
func resolveOptional(lib uintptr, name string, ptr any) {
	symbol, err := purego.Dlsym(lib, name)
	if err != nil {
		log.Debugf("keychain diagnostics: %s unavailable: %v", name, err)
		return
	}
	purego.RegisterFunc(ptr, symbol)
}
