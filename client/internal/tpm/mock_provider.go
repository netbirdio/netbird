package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
)

// MockProvider is an in-memory Provider implementation for tests.
// No real hardware is required. All keys are ephemeral ecdsa.PrivateKey values
// stored in a map keyed by keyID.
type MockProvider struct {
	mu    sync.RWMutex
	keys  map[string]*ecdsa.PrivateKey
	certs map[string]*x509.Certificate

	// AttestationProofFunc allows tests to override attestation behaviour.
	// If nil, AttestationProof returns a stub proof with dummy bytes.
	AttestationProofFunc func(ctx context.Context, keyID string) (*AttestationProof, error)

	// ActivateCredentialFunc allows tests to override ActivateCredential.
	// If nil, ActivateCredential returns an error indicating it is not configured.
	ActivateCredentialFunc func(ctx context.Context, credentialBlob []byte) ([]byte, error)

	// available controls the return value of Available(). Defaults to true.
	available bool
}

// NewMockProvider returns a MockProvider with Available() == true.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		keys:      make(map[string]*ecdsa.PrivateKey),
		certs:     make(map[string]*x509.Certificate),
		available: true,
	}
}

// NewUnavailableMockProvider returns a MockProvider that reports Available() == false.
func NewUnavailableMockProvider() *MockProvider {
	p := NewMockProvider()
	p.available = false
	return p
}

func (m *MockProvider) Available() bool {
	return m.available
}

func (m *MockProvider) GenerateKey(_ context.Context, keyID string) (crypto.Signer, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.keys[keyID]; ok {
		return existing, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m.keys[keyID] = key
	return key, nil
}

func (m *MockProvider) LoadKey(_ context.Context, keyID string) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *MockProvider) StoreCert(_ context.Context, keyID string, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.certs[keyID] = cert
	return nil
}

func (m *MockProvider) LoadCert(_ context.Context, keyID string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, ok := m.certs[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return cert, nil
}

func (m *MockProvider) AttestationProof(ctx context.Context, keyID string) (*AttestationProof, error) {
	if m.AttestationProofFunc != nil {
		return m.AttestationProofFunc(ctx, keyID)
	}
	// Return a minimal stub proof for tests that just need a non-nil value.
	return &AttestationProof{
		EKCert:      []byte("stub-ek-cert"),
		AKPublic:    []byte("stub-ak-public"),
		CertifyInfo: []byte("stub-certify-info"),
		Signature:   []byte("stub-signature"),
	}, nil
}

func (m *MockProvider) ActivateCredential(ctx context.Context, credentialBlob []byte) ([]byte, error) {
	if m.ActivateCredentialFunc != nil {
		return m.ActivateCredentialFunc(ctx, credentialBlob)
	}
	return nil, errors.New("tpm: MockProvider.ActivateCredential not configured")
}

// Keys returns a copy of the internal key map for test inspection.
func (m *MockProvider) Keys() map[string]*ecdsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]*ecdsa.PrivateKey, len(m.keys))
	for k, v := range m.keys {
		out[k] = v
	}
	return out
}
