// Package manager implements the per-account encrypted credential
// management surface. Plaintext secrets enter the manager via Create and
// leave via GetByRefWithSecret (the internal-only secret-returning path);
// every other public method returns metadata only.
package manager

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/management/internals/modules/credentials"
	"github.com/netbirdio/netbird/management/internals/modules/credentials/providertypes"
	"github.com/netbirdio/netbird/management/internals/modules/credentials/secretpayload"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/util/crypt"
)

// CredentialStore captures the subset of the management store interface
// the credentials manager depends on. The full store implementation
// lives in management/server/store; this narrow view simplifies tests.
type CredentialStore interface {
	CreateCredential(ctx context.Context, c *credentials.Credential) error
	GetCredentialByRef(ctx context.Context, accountID, ref string) (*credentials.Credential, error)
	ListCredentialsByAccount(ctx context.Context, accountID, providerTypeFilter string) ([]*credentials.Credential, error)
	UpdateCredential(ctx context.Context, c *credentials.Credential) error
	DeleteCredential(ctx context.Context, accountID, ref string) error
}

// EventRecorder captures the audit-log call site so the credentials
// manager can record reads without depending on the full account.Manager
// interface. The DefaultAccountManager (and any test stand-in) satisfies
// this implicitly.
type EventRecorder interface {
	StoreEvent(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
}

// Manager orchestrates credential CRUD with encryption-at-rest and audit.
type Manager struct {
	store  CredentialStore
	crypt  *crypt.FieldEncrypt
	events EventRecorder
}

// New constructs a credentials Manager.
func New(store CredentialStore, c *crypt.FieldEncrypt, events EventRecorder) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("credential store is required")
	}
	if c == nil {
		return nil, fmt.Errorf("crypt is required")
	}
	if events == nil {
		return nil, fmt.Errorf("event recorder is required")
	}
	return &Manager{store: store, crypt: c, events: events}, nil
}

// Create stores a new credential. The multi-field secret is JSON-encoded
// and then encrypted before persistence; the response carries metadata
// only — the caller never gets the plaintext back.
//
// Provider types are validated here against the closed-set registry.
// Adapters on the proxy side re-validate at issuance time as
// defense-in-depth.
func (m *Manager) Create(ctx context.Context, accountID, userID, providerType, name string, secretFields map[string]string) (*credentials.Credential, error) {
	if accountID == "" {
		return nil, fmt.Errorf("accountID is required")
	}
	if !providertypes.IsValid(providerType) {
		return nil, fmt.Errorf("provider_type %q is not one of %v", providerType, providertypes.All())
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if len(secretFields) == 0 {
		return nil, fmt.Errorf("secret_fields is required")
	}

	payload, err := secretpayload.Encode(secretFields)
	if err != nil {
		return nil, fmt.Errorf("encode secret payload: %w", err)
	}
	encrypted, err := m.crypt.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt credential: %w", err)
	}

	rec := &credentials.Credential{
		ID:              uuid.NewString(),
		AccountID:       accountID,
		ProviderType:    providerType,
		Name:            name,
		EncryptedSecret: encrypted,
	}
	if err := m.store.CreateCredential(ctx, rec); err != nil {
		return nil, fmt.Errorf("persist credential: %w", err)
	}

	m.events.StoreEvent(ctx, userID, rec.ID, accountID, activity.CredentialCreated, map[string]any{
		"provider_type": providerType,
	})

	// Return without the ciphertext to keep the boundary tight even on
	// the in-process call path.
	return scrubSecret(rec), nil
}

// GetMetadata returns the credential record without its secret. Safe to
// expose on HTTP responses. Does NOT emit an audit-log event because no
// secret material is decrypted.
func (m *Manager) GetMetadata(ctx context.Context, accountID, _ /* userID */, ref string) (*credentials.Credential, error) {
	if accountID == "" || ref == "" {
		return nil, fmt.Errorf("accountID and ref are required")
	}
	rec, err := m.store.GetCredentialByRef(ctx, accountID, ref)
	if err != nil {
		return nil, err
	}
	return scrubSecret(rec), nil
}

// GetByRefWithSecret returns the credential metadata plus the decrypted
// secret. Audit-logs the read. **Internal-only path** — never expose the
// plaintext to HTTP responses or any external surface.
func (m *Manager) GetByRefWithSecret(ctx context.Context, accountID, userID, ref string) (*credentials.Credential, string, error) {
	if accountID == "" || ref == "" {
		return nil, "", fmt.Errorf("accountID and ref are required")
	}
	rec, err := m.store.GetCredentialByRef(ctx, accountID, ref)
	if err != nil {
		return nil, "", err
	}
	plaintext, err := m.crypt.Decrypt(rec.EncryptedSecret)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt credential: %w", err)
	}
	m.events.StoreEvent(ctx, userID, ref, accountID, activity.CredentialRead, map[string]any{
		"provider_type": rec.ProviderType,
	})
	return scrubSecret(rec), plaintext, nil
}

// List returns all credentials for the account, optionally filtered by
// provider type. Secrets are scrubbed; safe for HTTP responses.
func (m *Manager) List(ctx context.Context, accountID, _ /* userID */, providerTypeFilter string) ([]*credentials.Credential, error) {
	if accountID == "" {
		return nil, fmt.Errorf("accountID is required")
	}
	recs, err := m.store.ListCredentialsByAccount(ctx, accountID, providerTypeFilter)
	if err != nil {
		return nil, err
	}
	out := make([]*credentials.Credential, len(recs))
	for i, r := range recs {
		out[i] = scrubSecret(r)
	}
	return out, nil
}

// Update overwrites the encrypted secret (and optionally the provider
// type and name) for an existing credential. Audit-logs the update.
// The ref is stable — services that reference this credential pick up
// the new secret on their next renewal.
func (m *Manager) Update(ctx context.Context, accountID, userID, ref, providerType, name string, secretFields map[string]string) (*credentials.Credential, error) {
	if accountID == "" || ref == "" {
		return nil, fmt.Errorf("accountID and ref are required")
	}
	if !providertypes.IsValid(providerType) {
		return nil, fmt.Errorf("provider_type %q is not one of %v", providerType, providertypes.All())
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if len(secretFields) == 0 {
		return nil, fmt.Errorf("secret_fields is required")
	}

	// Fetch existing record to confirm ownership before encrypting the
	// new secret. GetCredentialByRef is account-scoped and returns
	// NotFound for cross-account access.
	existing, err := m.store.GetCredentialByRef(ctx, accountID, ref)
	if err != nil {
		return nil, err
	}

	payload, err := secretpayload.Encode(secretFields)
	if err != nil {
		return nil, fmt.Errorf("encode secret payload: %w", err)
	}
	encrypted, err := m.crypt.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt credential: %w", err)
	}

	existing.ProviderType = providerType
	existing.Name = name
	existing.EncryptedSecret = encrypted
	if err := m.store.UpdateCredential(ctx, existing); err != nil {
		return nil, fmt.Errorf("persist updated credential: %w", err)
	}

	m.events.StoreEvent(ctx, userID, ref, accountID, activity.CredentialUpdated, map[string]any{
		"provider_type": providerType,
	})

	return scrubSecret(existing), nil
}

// Delete removes a credential record. Audit-logs the deletion.
func (m *Manager) Delete(ctx context.Context, accountID, userID, ref string) error {
	if accountID == "" || ref == "" {
		return fmt.Errorf("accountID and ref are required")
	}
	rec, err := m.store.GetCredentialByRef(ctx, accountID, ref)
	if err != nil {
		return err
	}
	if err := m.store.DeleteCredential(ctx, accountID, ref); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	m.events.StoreEvent(ctx, userID, ref, accountID, activity.CredentialDeleted, map[string]any{
		"provider_type": rec.ProviderType,
	})
	return nil
}

// scrubSecret returns a shallow copy of rec with the EncryptedSecret
// field zeroed. The original record is unchanged. Use whenever a record
// will leave the management server's internal call boundary.
func scrubSecret(rec *credentials.Credential) *credentials.Credential {
	if rec == nil {
		return nil
	}
	cp := *rec
	cp.EncryptedSecret = ""
	return &cp
}
