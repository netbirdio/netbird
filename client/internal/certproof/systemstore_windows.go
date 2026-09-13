package certproof

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	personalStore     = "MY"
	intermediateStore = "CA"

	cryptAcquireSilentFlag          = 0x00000040
	cryptAcquirePreferNCryptKeyFlag = 0x00020000
	certNCryptKeySpec               = 0xFFFFFFFF
	bcryptPadPSS                    = 0x00000008
)

var (
	crypt32 = windows.NewLazySystemDLL("crypt32.dll")
	ncrypt  = windows.NewLazySystemDLL("ncrypt.dll")

	procCryptAcquireCertificatePrivateKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procNCryptSignHash                    = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject                  = ncrypt.NewProc("NCryptFreeObject")
)

type bcryptPSSPaddingInfo struct {
	algID *uint16
	salt  uint32
}

// DefaultStore is the local machine's personal certificate store, where device
// certificates enrolled through AD or Intune are kept.
func DefaultStore() Store {
	return NewSystemStore()
}

// SystemStore yields the identities of a personal certificate store, completing their
// chains from the matching intermediate CA store. Keys are used through CNG and never
// exported.
//
// The location decides whose certificates these are. The local machine store is the one
// a service reads; the current user store lives in the signed-in user's registry hive
// with keys protected against their profile, so it is only readable while running as
// that user.
type SystemStore struct {
	location uint32
}

// NewSystemStore reads the local machine store, which is what the daemon uses.
func NewSystemStore() *SystemStore {
	return &SystemStore{location: windows.CERT_SYSTEM_STORE_LOCAL_MACHINE}
}

// NewUserStore reads the calling user's personal store. It is only useful in a process
// already running as that user, which is what the posture helper is.
func NewUserStore() *SystemStore {
	return &SystemStore{location: windows.CERT_SYSTEM_STORE_CURRENT_USER}
}

func (s *SystemStore) Candidates(_ context.Context) ([]Candidate, error) {
	leaves, err := storeCertificates(s.location, personalStore)
	if err != nil {
		return nil, err
	}
	intermediates, err := storeCertificates(s.location, intermediateStore)
	if err != nil {
		return nil, err
	}
	log.Infof("certificate store %s holds %d personal certificates and %d intermediates", s, len(leaves), len(intermediates))
	if len(leaves) == 0 {
		return nil, nil
	}

	pool := slices.Concat(intermediates, leaves)
	candidates := make([]Candidate, 0, len(leaves))
	for _, leaf := range leaves {
		chain := buildChain(leaf, pool)
		log.Infof("certificate store %s candidate %q issued by %q built a chain of %d certificates", s, leaf.Subject, leaf.Issuer, len(chain))
		candidates = append(candidates, Candidate{Chain: chain, Signer: &systemStoreSigner{leaf: leaf, location: s.location}})
	}
	return candidates, nil
}

// String names the store location the way the Windows documentation does.
func (s *SystemStore) String() string {
	if s.location == windows.CERT_SYSTEM_STORE_CURRENT_USER {
		return "CurrentUser"
	}
	return "LocalMachine"
}

// systemStoreSigner holds only the certificate; the store entry and its key are acquired
// at signing time so no handles outlive a call.
type systemStoreSigner struct {
	leaf     *x509.Certificate
	location uint32
}

func (s *systemStoreSigner) Public() crypto.PublicKey {
	return s.leaf.PublicKey
}

func (s *systemStoreSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	scheme, err := schemeFor(s.leaf.PublicKey, opts)
	if err != nil {
		return nil, err
	}
	store, err := openStore(s.location, personalStore)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	var signature []byte
	err = eachCertificate(store, func(ctx *windows.CertContext) (bool, error) {
		if !bytes.Equal(encodedCert(ctx), s.leaf.Raw) {
			return false, nil
		}
		signature, err = signWithContext(ctx, scheme, digest)
		return true, err
	})
	if err != nil {
		return nil, err
	}
	if signature == nil {
		return nil, errors.New("certificate is no longer in the personal store")
	}
	return signature, nil
}

func signWithContext(ctx *windows.CertContext, scheme sigScheme, digest []byte) ([]byte, error) {
	var key uintptr
	var keySpec uint32
	var callerFree int32
	ok, _, err := procCryptAcquireCertificatePrivateKey.Call(uintptr(unsafe.Pointer(ctx)), cryptAcquireSilentFlag|cryptAcquirePreferNCryptKeyFlag, 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&keySpec)), uintptr(unsafe.Pointer(&callerFree)))
	if ok == 0 {
		return nil, fmt.Errorf("acquire private key: %w", err)
	}
	if keySpec != certNCryptKeySpec {
		if callerFree != 0 {
			_ = windows.CryptReleaseContext(windows.Handle(key), 0)
		}
		return nil, errors.New("legacy CryptoAPI keys are not supported")
	}
	if callerFree != 0 {
		defer func() { _, _, _ = procNCryptFreeObject.Call(key) }()
	}

	var padding unsafe.Pointer
	var flags uintptr
	if scheme == schemeRSAPSSSHA256 {
		algID, _ := windows.UTF16PtrFromString("SHA256")
		info := bcryptPSSPaddingInfo{algID: algID, salt: sha256.Size}
		padding, flags = unsafe.Pointer(&info), bcryptPadPSS
	}
	size, err := ncryptSignHash(key, padding, digest, nil, flags)
	if err != nil {
		return nil, err
	}
	signature := make([]byte, size)
	if size, err = ncryptSignHash(key, padding, digest, signature, flags); err != nil {
		return nil, err
	}
	signature = signature[:size]
	if scheme == schemeRSAPSSSHA256 {
		return signature, nil
	}
	return ecdsaSignatureASN1(signature)
}

func ncryptSignHash(key uintptr, padding unsafe.Pointer, digest, signature []byte, flags uintptr) (uint32, error) {
	var result uint32
	var signaturePtr uintptr
	if len(signature) > 0 {
		signaturePtr = uintptr(unsafe.Pointer(&signature[0]))
	}
	status, _, _ := procNCryptSignHash.Call(key, uintptr(padding), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		signaturePtr, uintptr(len(signature)), uintptr(unsafe.Pointer(&result)), flags)
	if uint32(status) != 0 {
		return 0, fmt.Errorf("NCryptSignHash: 0x%08x", uint32(status))
	}
	return result, nil
}

func storeCertificates(location uint32, name string) ([]*x509.Certificate, error) {
	store, err := openStore(location, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	var certs []*x509.Certificate
	err = eachCertificate(store, func(ctx *windows.CertContext) (bool, error) {
		cert, err := x509.ParseCertificate(bytes.Clone(encodedCert(ctx)))
		if err != nil {
			log.Warnf("skipping certificate in %s store: %v", name, err)
			return false, nil
		}
		certs = append(certs, cert)
		return false, nil
	})
	return certs, err
}

func openStore(location uint32, name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := location | uint32(windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG)
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(namePtr)))
	if err != nil {
		return 0, fmt.Errorf("open %s certificate store: %w", name, err)
	}
	return store, nil
}

func eachCertificate(store windows.Handle, fn func(*windows.CertContext) (bool, error)) error {
	var ctx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, ctx)
		if next == nil {
			if errors.Is(err, windows.Errno(windows.CRYPT_E_NOT_FOUND)) || errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return nil
			}
			return fmt.Errorf("enumerate certificates: %w", err)
		}
		ctx = next
		if stop, err := fn(ctx); stop || err != nil {
			_ = windows.CertFreeCertificateContext(ctx)
			return err
		}
	}
}

func encodedCert(ctx *windows.CertContext) []byte {
	return unsafe.Slice(ctx.EncodedCert, ctx.Length)
}
