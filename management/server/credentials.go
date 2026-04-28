package server

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/credentials"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/management/status"
)

// CreateCredential stores a new encrypted credential record for an account.
// The plaintext secret is encrypted before persistence; the response carries
// metadata only.
func (am *DefaultAccountManager) CreateCredential(ctx context.Context, accountID, userID, providerType, name string, secretFields map[string]string) (*credentials.Credential, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Credentials, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}
	if am.credentialsManager == nil {
		return nil, status.Errorf(status.Internal, "credential storage is not configured (missing data store encryption key)")
	}
	rec, err := am.credentialsManager.Create(ctx, accountID, userID, providerType, name, secretFields)
	if err != nil {
		return nil, fmt.Errorf("create credential: %w", err)
	}
	return rec, nil
}

// GetCredentialMetadata returns a single credential's metadata (no secret).
func (am *DefaultAccountManager) GetCredentialMetadata(ctx context.Context, accountID, userID, ref string) (*credentials.Credential, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Credentials, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}
	if am.credentialsManager == nil {
		return nil, status.Errorf(status.NotFound, "credential %s not found", ref)
	}
	return am.credentialsManager.GetMetadata(ctx, accountID, userID, ref)
}

// ListCredentials returns all credentials for the account, optionally filtered
// by provider type. Secrets are scrubbed.
func (am *DefaultAccountManager) ListCredentials(ctx context.Context, accountID, userID, providerTypeFilter string) ([]*credentials.Credential, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Credentials, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}
	if am.credentialsManager == nil {
		return []*credentials.Credential{}, nil
	}
	return am.credentialsManager.List(ctx, accountID, userID, providerTypeFilter)
}

// UpdateCredential overwrites the encrypted secret (and optionally the
// provider type and name) for an existing credential. The ref is stable.
func (am *DefaultAccountManager) UpdateCredential(ctx context.Context, accountID, userID, ref, providerType, name string, secretFields map[string]string) (*credentials.Credential, error) {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Credentials, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}
	if am.credentialsManager == nil {
		return nil, status.Errorf(status.Internal, "credential storage is not configured (missing data store encryption key)")
	}
	rec, err := am.credentialsManager.Update(ctx, accountID, userID, ref, providerType, name, secretFields)
	if err != nil {
		return nil, fmt.Errorf("update credential: %w", err)
	}
	return rec, nil
}

// ResolveCredentialSecret returns the decrypted secret + provider type
// for a credential ref. Internal-only path for the proxy↔mgmt
// ResolveCredential gRPC handler. Audit-logs the read via the
// underlying credentials manager. Permission checks are deliberately
// not applied here — this method is only callable from internal gRPC
// code paths whose own authentication has already been validated.
func (am *DefaultAccountManager) ResolveCredentialSecret(ctx context.Context, accountID, ref string) (string, string, error) {
	if am.credentialsManager == nil {
		return "", "", status.Errorf(status.NotFound, "credential %s not found", ref)
	}
	rec, plaintext, err := am.credentialsManager.GetByRefWithSecret(ctx, accountID, "system", ref)
	if err != nil {
		return "", "", err
	}
	return plaintext, rec.ProviderType, nil
}

// DeleteCredential removes a credential record.
func (am *DefaultAccountManager) DeleteCredential(ctx context.Context, accountID, userID, ref string) error {
	ok, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Credentials, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}
	if am.credentialsManager == nil {
		return status.Errorf(status.NotFound, "credential %s not found", ref)
	}
	return am.credentialsManager.Delete(ctx, accountID, userID, ref)
}
