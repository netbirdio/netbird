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

// SystemStore yields the identities of the local machine's personal store, completing
// their chains from the intermediate CA store. Keys are used through CNG and never exported.
type SystemStore struct{}

func NewSystemStore() *SystemStore {
	return &SystemStore{}
}

func (s *SystemStore) Candidates(_ context.Context) ([]Candidate, error) {
	leaves, err := storeCertificates(personalStore)
	if err != nil || len(leaves) == 0 {
		return nil, err
	}
	intermediates, err := storeCertificates(intermediateStore)
	if err != nil {
		return nil, err
	}
	pool := slices.Concat(intermediates, leaves)
	candidates := make([]Candidate, 0, len(leaves))
	for _, leaf := range leaves {
		candidates = append(candidates, Candidate{Chain: buildChain(leaf, pool), Signer: &systemStoreSigner{leaf: leaf}})
	}
	return candidates, nil
}

// systemStoreSigner holds only the certificate; the store entry and its key are acquired
// at signing time so no handles outlive a call.
type systemStoreSigner struct {
	leaf *x509.Certificate
}

func (s *systemStoreSigner) Public() crypto.PublicKey {
	return s.leaf.PublicKey
}

func (s *systemStoreSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	scheme, err := schemeFor(s.leaf.PublicKey, opts)
	if err != nil {
		return nil, err
	}
	store, err := openStore(personalStore)
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

func storeCertificates(name string) ([]*x509.Certificate, error) {
	store, err := openStore(name)
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

func openStore(name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE | windows.CERT_STORE_READONLY_FLAG | windows.CERT_STORE_OPEN_EXISTING_FLAG)
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
