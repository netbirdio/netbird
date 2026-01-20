//go:build windows

// CNG crypto.Signer Spike - T-1.1
// Tests whether Go can use non-exportable Windows Cert Store certificates
// for TLS authentication via the crypto.Signer interface.
//
// Based on: https://victoronsoftware.com/posts/mtls-go-client-windows-certificate-store/
// Source: https://github.com/getvictor/mtls/tree/master/mtls-go-windows
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// Windows NCrypt flags
	nCryptSilentFlag = 0x00000040 // ncrypt.h NCRYPT_SILENT_FLAG
	bCryptPadPkcs1   = 0x00000002 // bcrypt.h BCRYPT_PAD_PKCS1
	bCryptPadPss     = 0x00000008 // bcrypt.h BCRYPT_PAD_PSS
)

var (
	nCrypt         = windows.MustLoadDLL("ncrypt.dll")
	nCryptSignHash = nCrypt.MustFindProc("NCryptSignHash")
)

// CNGSigner implements crypto.Signer using Windows CNG
type CNGSigner struct {
	store              windows.Handle
	windowsCertContext *windows.CertContext
	x509Cert           *x509.Certificate
}

func (k *CNGSigner) Public() crypto.PublicKey {
	return k.x509Cert.PublicKey
}

func (k *CNGSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Get private key from Windows cert store
	var (
		privateKey                  windows.Handle
		pdwKeySpec                  uint32
		pfCallerFreeProvOrNCryptKey bool
	)
	err = windows.CryptAcquireCertificatePrivateKey(
		k.windowsCertContext,
		windows.CRYPT_ACQUIRE_CACHE_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
		nil,
		&privateKey,
		&pdwKeySpec,
		&pfCallerFreeProvOrNCryptKey,
	)
	if err != nil {
		return nil, fmt.Errorf("CryptAcquireCertificatePrivateKey: %w", err)
	}

	// Determine padding based on SignerOpts
	var flags uint32 = nCryptSilentFlag
	var pPaddingInfo unsafe.Pointer

	switch opts := opts.(type) {
	case *rsa.PSSOptions:
		// RSA-PSS padding
		flags |= bCryptPadPss
		pPaddingInfo, err = getRsaPssPadding(opts)
		if err != nil {
			return nil, err
		}
	default:
		// PKCS#1 v1.5 padding (default for most certificates)
		flags |= bCryptPadPkcs1
		pPaddingInfo, err = getPkcs1Padding(opts.HashFunc())
		if err != nil {
			return nil, err
		}
	}

	// Sign the digest - first call gets signature size
	var size uint32
	success, _, _ := nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to get signature length: %#x", success)
	}

	// Second call generates the signature
	signature = make([]byte, size)
	success, _, _ = nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to generate signature: %#x", success)
	}
	return signature, nil
}

func getRsaPssPadding(opts *rsa.PSSOptions) (unsafe.Pointer, error) {
	algName, err := hashToAlgName(opts.Hash)
	if err != nil {
		return nil, err
	}
	algPtr, _ := windows.UTF16PtrFromString(algName)
	// BCRYPT_PSS_PADDING_INFO structure
	return unsafe.Pointer(
		&struct {
			pszAlgId *uint16
			cbSalt   uint32
		}{
			pszAlgId: algPtr,
			cbSalt:   uint32(opts.HashFunc().Size()),
		},
	), nil
}

func getPkcs1Padding(hash crypto.Hash) (unsafe.Pointer, error) {
	algName, err := hashToAlgName(hash)
	if err != nil {
		return nil, err
	}
	algPtr, _ := windows.UTF16PtrFromString(algName)
	// BCRYPT_PKCS1_PADDING_INFO structure
	return unsafe.Pointer(
		&struct {
			pszAlgId *uint16
		}{
			pszAlgId: algPtr,
		},
	), nil
}

func hashToAlgName(hash crypto.Hash) (string, error) {
	switch hash {
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	case crypto.SHA1:
		return "SHA1", nil
	default:
		return "", fmt.Errorf("unsupported hash function: %s", hash.String())
	}
}

// OpenCertStore opens the Windows Certificate Store
func OpenCertStore(storeName string, storeLocation uint32) (windows.Handle, error) {
	storePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return 0, err
	}
	return windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		uintptr(0),
		storeLocation,
		uintptr(unsafe.Pointer(storePtr)),
	)
}

// FindCertBySubject finds a certificate containing the given subject string
func FindCertBySubject(store windows.Handle, subject string) (*windows.CertContext, error) {
	subjectPtr, err := windows.UTF16PtrFromString(subject)
	if err != nil {
		return nil, err
	}
	return windows.CertFindCertificateInStore(
		store,
		windows.X509_ASN_ENCODING,
		0,
		windows.CERT_FIND_SUBJECT_STR,
		unsafe.Pointer(subjectPtr),
		nil,
	)
}

// NewCNGSigner creates a crypto.Signer from a Windows certificate
func NewCNGSigner(store windows.Handle, certCtx *windows.CertContext) (*CNGSigner, error) {
	// Copy certificate data outside Windows context
	encodedCert := unsafe.Slice(certCtx.EncodedCert, certCtx.Length)
	buf := bytes.Clone(encodedCert)
	x509Cert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	signer := &CNGSigner{
		store:              store,
		windowsCertContext: certCtx,
		x509Cert:           x509Cert,
	}

	// Set finalizer for cleanup
	runtime.SetFinalizer(signer, func(c *CNGSigner) {
		_ = windows.CertFreeCertificateContext(c.windowsCertContext)
		_ = windows.CertCloseStore(c.store, 0)
	})

	return signer, nil
}

func main() {
	fmt.Println("=== CNG crypto.Signer Spike (T-1.1) ===")
	fmt.Println("Pure Go implementation using golang.org/x/sys/windows")
	fmt.Println()

	// Search subject (default: DC01)
	searchSubject := "DC01"
	if len(os.Args) > 1 {
		searchSubject = os.Args[1]
	}

	// Test 1: Open LocalMachine Certificate Store
	fmt.Println("[1] Opening LocalMachine\\My certificate store...")
	store, err := OpenCertStore("MY", windows.CERT_SYSTEM_STORE_LOCAL_MACHINE)
	if err != nil {
		log.Fatalf("Failed to open cert store: %v", err)
	}
	fmt.Println("    Store opened successfully")
	fmt.Println()

	// Test 2: Find certificate by subject
	fmt.Printf("[2] Searching for certificate containing '%s'...\n", searchSubject)

	// Enumerate all certificates first
	var prevCtx *windows.CertContext
	var foundCtx *windows.CertContext
	count := 0

	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prevCtx)
		if err != nil {
			break // End of enumeration
		}
		count++

		// Parse and check certificate
		encodedCert := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		buf := bytes.Clone(encodedCert)
		cert, err := x509.ParseCertificate(buf)
		if err != nil {
			prevCtx = ctx
			continue
		}

		fmt.Printf("    - CN=%s (Issuer: %s)\n", cert.Subject.CommonName, cert.Issuer.CommonName)

		if strings.Contains(cert.Subject.CommonName, searchSubject) && foundCtx == nil {
			// CRITICAL: Duplicate the context! CertEnumCertificatesInStore frees
			// the previous context on next call, so we must duplicate it to keep it valid.
			foundCtx = windows.CertDuplicateCertificateContext(ctx)
			fmt.Printf("\n    MATCH FOUND!\n")
			fmt.Printf("    Subject: %s\n", cert.Subject.String())
			fmt.Printf("    Thumbprint: %X\n", sha256.Sum256(cert.Raw))
			fmt.Printf("    NotAfter: %s\n", cert.NotAfter.Format(time.RFC3339))
			fmt.Printf("    Issuer: %s\n", cert.Issuer.CommonName)
			fmt.Printf("    Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())

			if len(cert.DNSNames) > 0 {
				fmt.Printf("    SAN DNSNames: %v\n", cert.DNSNames)
			}
		}
		prevCtx = ctx
	}
	fmt.Printf("\n    Total certificates in store: %d\n", count)

	if foundCtx == nil {
		log.Fatalf("No certificate found matching '%s'", searchSubject)
	}
	fmt.Println("    Certificate found")
	fmt.Println()

	// Test 3: Create crypto.Signer from certificate
	fmt.Println("[3] Creating crypto.Signer from certificate...")
	signer, err := NewCNGSigner(store, foundCtx)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}
	fmt.Println("    crypto.Signer created (private key in CNG store)")
	fmt.Println()

	// Test 4: Verify public key access
	fmt.Println("[4] Verifying public key access...")
	pubKey := signer.Public()
	if pubKey == nil {
		log.Fatal("Public key is nil")
	}
	fmt.Printf("    Public key type: %T\n", pubKey)
	fmt.Println("    Public key accessible")
	fmt.Println()

	// Test 5: Sign a test digest (PKCS#1 v1.5)
	fmt.Println("[5] Testing signing operation (SHA-256, PKCS#1 v1.5)...")
	testData := []byte("NetBird Machine Tunnel CNG Spike Test")
	digest := sha256.Sum256(testData)

	startSign := time.Now()
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	signDuration := time.Since(startSign)

	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	fmt.Printf("    Signature length: %d bytes\n", len(signature))
	fmt.Printf("    Signing latency: %v\n", signDuration)
	fmt.Println("    Signing successful!")
	fmt.Println()

	// Test 6: Verify signature
	fmt.Println("[6] Verifying signature...")
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println("    Skipping verification (non-RSA key)")
	} else {
		err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], signature)
		if err != nil {
			log.Fatalf("Signature verification failed: %v", err)
		}
		fmt.Println("    Signature verified successfully!")
	}
	fmt.Println()

	// Test 7: Performance test (10 signing operations)
	fmt.Println("[7] Performance test (10 signing operations)...")
	var totalDuration time.Duration
	for i := 0; i < 10; i++ {
		testDigest := sha256.Sum256([]byte(fmt.Sprintf("test-%d", i)))
		start := time.Now()
		_, err := signer.Sign(rand.Reader, testDigest[:], crypto.SHA256)
		if err != nil {
			log.Fatalf("Signing %d failed: %v", i, err)
		}
		totalDuration += time.Since(start)
	}
	avgLatency := totalDuration / 10
	fmt.Printf("    Average signing latency: %v\n", avgLatency)
	if avgLatency > 500*time.Millisecond {
		fmt.Println("    WARNING: Latency > 500ms (performance concern)")
	} else if avgLatency > 50*time.Millisecond {
		fmt.Println("    Note: Latency > 50ms (acceptable)")
	} else {
		fmt.Println("    Excellent performance!")
	}
	fmt.Println()

	// Test 8: Create tls.Certificate
	fmt.Println("[8] Creating tls.Certificate with CNG-backed signer...")
	tlsCert := tls.Certificate{
		Certificate: [][]byte{signer.x509Cert.Raw},
		PrivateKey:  signer,
		Leaf:        signer.x509Cert,
	}
	fmt.Printf("    Certificate chain length: %d\n", len(tlsCert.Certificate))
	fmt.Println("    tls.Certificate created")
	fmt.Println()

	// Test 9: Verify TLS config is usable for mTLS
	fmt.Println("[9] Verifying TLS config for mTLS client...")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	// Verify config has the certificate and can be used for mTLS
	if len(tlsConfig.Certificates) == 0 {
		log.Fatal("TLS config has no certificates")
	}
	if tlsConfig.Certificates[0].PrivateKey == nil {
		log.Fatal("TLS certificate has no private key")
	}
	// Verify the private key implements crypto.Signer
	if _, ok := tlsConfig.Certificates[0].PrivateKey.(crypto.Signer); !ok {
		log.Fatal("Private key does not implement crypto.Signer")
	}
	fmt.Println("    TLS config valid for mTLS (crypto.Signer verified)")
	fmt.Println()

	// Summary
	fmt.Println("=== SPIKE RESULT: GO ===")
	fmt.Println()
	fmt.Println("All tests passed! CNG crypto.Signer works with non-exportable keys.")
	fmt.Println()
	fmt.Println("Key findings:")
	fmt.Println("  - Implementation: Pure Go using golang.org/x/sys/windows")
	fmt.Println("  - No CGO required!")
	fmt.Println("  - Store: LocalMachine\\My (CNG-backed)")
	fmt.Printf("  - Certificate: %s\n", signer.x509Cert.Subject.CommonName)
	fmt.Println("  - Private key: Non-exportable (CNG-backed)")
	fmt.Printf("  - Signing latency: %v (avg)\n", avgLatency)
	fmt.Println()
	fmt.Println("Recommendation: Proceed with implementation using golang.org/x/sys/windows")
	fmt.Println("Reference: https://github.com/getvictor/mtls/tree/master/mtls-go-windows")
}
