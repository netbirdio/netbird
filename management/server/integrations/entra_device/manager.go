package entra_device

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
)

// PeerEnroller is the callback the Manager invokes after resolving a mapping
// to actually create the NetBird peer. In phase 1 this is wired to a
// closure that calls AccountManager.AddPeer. Keeping it as an interface
// avoids a hard dependency on the main AccountManager here.
type PeerEnroller interface {
	EnrollEntraDevicePeer(ctx context.Context, in EnrollPeerInput) (*EnrollPeerResult, error)
	// DeletePeer best-effort-compensates a just-enrolled peer when a
	// downstream step (e.g. bootstrap-token issuance) fails. Implementations
	// should be idempotent and quiet on "already gone".
	DeletePeer(ctx context.Context, accountID, peerID string) error
}

// EnrollPeerInput is the data the PeerEnroller needs to create the peer.
type EnrollPeerInput struct {
	AccountID           string
	EntraDeviceID       string
	EntraDeviceMapping  string
	AutoGroups          []string
	Ephemeral           bool
	AllowExtraDNSLabels bool
	ExpiresAt           *time.Time
	ResolutionMode      string
	MatchedMappingIDs   []string
	WGPubKey            string
	SSHPubKey           string
	Hostname            string
	DNSLabels           []string
	ExtraDNSLabels      []string
	ConnectionIP        string
}

// EnrollPeerResult is what the PeerEnroller returns back to the Manager after
// it creates the peer.
type EnrollPeerResult struct {
	PeerID        string
	NetbirdConfig map[string]any
	PeerConfig    map[string]any
	Checks        []map[string]any
}

// Manager orchestrates the challenge/enroll flow. It is lock-free; the Store
// and NonceStore handle their own concurrency.
type Manager struct {
	Store        Store
	NonceStore   NonceStore
	Cert         *CertValidator
	NewGraph     func(tenantID, clientID, clientSecret string) GraphClient
	PeerEnroller PeerEnroller

	// Clock overridable for tests.
	Clock func() time.Time
}

// NewManager constructs a manager with sensible defaults. Callers are expected
// to set PeerEnroller before handling enrolments.
func NewManager(store Store) *Manager {
	return &Manager{
		Store:      store,
		NonceStore: NewInMemoryNonceStore(0),
		Cert:       NewCertValidator(nil, nil),
		NewGraph: func(tenantID, clientID, clientSecret string) GraphClient {
			return NewHTTPGraphClient(tenantID, clientID, clientSecret)
		},
		Clock: func() time.Time { return time.Now().UTC() },
	}
}

// IssueChallenge produces a single-use nonce for the client to sign.
func (m *Manager) IssueChallenge(_ context.Context) (*ChallengeResponse, error) {
	nonce, exp, err := m.NonceStore.Issue()
	if err != nil {
		return nil, NewError(CodeInternal, "failed to issue nonce", err)
	}
	return &ChallengeResponse{Nonce: nonce, ExpiresAt: exp}, nil
}

// Enroll executes the full enrolment flow: nonce check, cert + signature,
// Graph lookups, mapping resolution, peer creation, bootstrap token issuance.
//
// Each numbered step is extracted into its own helper to keep this function
// at a reviewable size and bound its cognitive complexity.
func (m *Manager) Enroll(ctx context.Context, req *EnrollRequest) (*EnrollResponse, error) {
	if req == nil {
		return nil, NewError(CodeInternal, "nil request", nil)
	}
	if req.TenantID == "" {
		return nil, NewError(CodeIntegrationNotFound, "tenant_id is required", nil)
	}

	auth, err := m.loadEnabledIntegration(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	nonceBytes, err := m.consumeNonce(req.Nonce)
	if err != nil {
		return nil, err
	}
	identity, err := m.validateCertAndDeviceID(req, nonceBytes)
	if err != nil {
		return nil, err
	}
	if err := m.verifyWithGraph(ctx, auth, identity); err != nil {
		return nil, err
	}
	resolved, err := m.resolveMappingForAccount(ctx, auth, identity)
	if err != nil {
		return nil, err
	}
	result, err := m.enrollPeer(ctx, auth, identity, resolved, req)
	if err != nil {
		return nil, err
	}
	token, err := m.issueBootstrapToken(ctx, result.PeerID)
	if err != nil {
		// Best-effort compensation: the peer has been created but the
		// bootstrap token could not be persisted. Leaving the peer behind
		// means the device is stuck (duplicate-pubkey on retry) until an
		// admin deletes it, so delete it now and surface the original error.
		if delErr := m.PeerEnroller.DeletePeer(ctx, auth.AccountID, result.PeerID); delErr != nil {
			return nil, NewError(CodeInternal,
				fmt.Sprintf("failed to issue bootstrap token; orphan-peer compensation also failed: %v", delErr), err)
		}
		return nil, err
	}
	return &EnrollResponse{
		PeerID:                   result.PeerID,
		EnrollmentBootstrapToken: token,
		ResolvedAutoGroups:       resolved.AutoGroups,
		MatchedMappingIDs:        resolved.MatchedMappingIDs,
		ResolutionMode:           resolved.ResolutionMode,
		NetbirdConfig:            result.NetbirdConfig,
		PeerConfig:               result.PeerConfig,
		Checks:                   result.Checks,
	}, nil
}

// loadEnabledIntegration fetches the EntraDeviceAuth config for a tenant
// and verifies it is enabled.
func (m *Manager) loadEnabledIntegration(ctx context.Context, tenantID string) (*types.EntraDeviceAuth, error) {
	auth, err := m.Store.GetEntraDeviceAuthByTenant(ctx, tenantID)
	if err != nil {
		return nil, NewError(CodeInternal, "failed to load integration", err)
	}
	if auth == nil {
		return nil, NewError(CodeIntegrationNotFound,
			fmt.Sprintf("no Entra device auth integration is configured for tenant %s", tenantID), nil)
	}
	if !auth.Enabled {
		return nil, NewError(CodeIntegrationDisabled,
			"Entra device auth integration is disabled for this tenant", nil)
	}
	return auth, nil
}

// consumeNonce atomically marks the supplied nonce as used and returns its
// raw bytes (what the signer signed over).
func (m *Manager) consumeNonce(encoded string) ([]byte, error) {
	// Normalise once so Consume and decodeNonceBytes see the same value —
	// otherwise a trailing newline would be accepted by Consume (which
	// trims) and then fail base64 decode, burning the nonce with no way to
	// retry.
	encoded = strings.TrimSpace(encoded)
	ok, err := m.NonceStore.Consume(encoded)
	if err != nil {
		return nil, NewError(CodeInternal, "nonce store error", err)
	}
	if !ok {
		return nil, NewError(CodeInvalidNonce, "nonce is unknown, already consumed, or expired", nil)
	}
	return decodeNonceBytes(encoded)
}

// decodeNonceBytes tolerates both RawURL and Std base64 alphabets.
func decodeNonceBytes(encoded string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return nil, NewError(CodeInvalidNonce, "nonce is not base64", nil)
}

// validateCertAndDeviceID verifies the cert chain + signature proof and
// cross-checks the client-supplied device id when one is present.
func (m *Manager) validateCertAndDeviceID(req *EnrollRequest, nonceBytes []byte) (*DeviceIdentity, error) {
	identity, verr := m.Cert.Validate(req.CertChain, nonceBytes, req.NonceSignature)
	if verr != nil {
		return nil, verr
	}
	// Fail closed: cert_validator may surface an identity with an empty
	// EntraDeviceID if CommonName was absent; reject here rather than
	// letting an empty id flow into Graph + audit log.
	if identity.EntraDeviceID == "" {
		return nil, NewError(CodeInvalidCertChain,
			"leaf certificate does not contain an Entra device id", nil)
	}
	if req.EntraDeviceID != "" && !strings.EqualFold(req.EntraDeviceID, identity.EntraDeviceID) {
		return nil, NewError(CodeInvalidCertChain,
			fmt.Sprintf("device id mismatch: cert=%s, request=%s", identity.EntraDeviceID, req.EntraDeviceID), nil)
	}
	return identity, nil
}

// verifyWithGraph talks to Microsoft Graph to confirm the device exists,
// is enabled, enumerate groups, and (optionally) verify Intune compliance.
func (m *Manager) verifyWithGraph(ctx context.Context, auth *types.EntraDeviceAuth, identity *DeviceIdentity) error {
	graph := m.NewGraph(auth.TenantID, auth.ClientID, auth.ClientSecret)

	device, err := graph.Device(ctx, identity.EntraDeviceID)
	if err != nil {
		return NewError(CodeGroupLookupFailed, "graph device lookup failed", err)
	}
	if device == nil {
		return NewError(CodeDeviceDisabled, "device not found in Entra; has it been deleted?", nil)
	}
	if !device.AccountEnabled {
		return NewError(CodeDeviceDisabled, "device is disabled in Entra", nil)
	}
	identity.AccountEnabled = true

	groups, err := graph.TransitiveMemberOf(ctx, device.ID)
	if err != nil {
		return NewError(CodeGroupLookupFailed, "graph transitiveMemberOf failed", err)
	}
	identity.GroupIDs = groups

	if !auth.RequireIntuneCompliant {
		return nil
	}
	compliant, err := graph.IsCompliant(ctx, identity.EntraDeviceID)
	if err != nil {
		return NewError(CodeGroupLookupFailed, "graph Intune compliance lookup failed", err)
	}
	if !compliant {
		return NewError(CodeDeviceNotCompliant, "device is not compliant in Intune", nil)
	}
	identity.IsCompliant = true
	return nil
}

// resolveMappingForAccount reads the account's mapping rows and runs the
// resolver against the device's Entra groups.
func (m *Manager) resolveMappingForAccount(ctx context.Context, auth *types.EntraDeviceAuth, identity *DeviceIdentity) (*ResolvedMapping, error) {
	mappings, err := m.Store.ListEntraDeviceMappings(ctx, auth.AccountID)
	if err != nil {
		return nil, NewError(CodeInternal, "failed to list mappings", err)
	}
	resolved, verr := ResolveMapping(auth, mappings, identity.GroupIDs)
	if verr != nil {
		return nil, verr
	}
	return resolved, nil
}

// enrollPeer hands the resolved configuration off to the AccountManager-side
// PeerEnroller (creates the peer, assigns auto-groups, etc).
func (m *Manager) enrollPeer(ctx context.Context, auth *types.EntraDeviceAuth, identity *DeviceIdentity, resolved *ResolvedMapping, req *EnrollRequest) (*EnrollPeerResult, error) {
	if m.PeerEnroller == nil {
		return nil, NewError(CodeInternal, "server not configured to enroll peers", nil)
	}
	in := EnrollPeerInput{
		AccountID:           auth.AccountID,
		EntraDeviceID:       identity.EntraDeviceID,
		AutoGroups:          resolved.AutoGroups,
		Ephemeral:           resolved.Ephemeral,
		AllowExtraDNSLabels: resolved.AllowExtraDNSLabels,
		ExpiresAt:           resolved.ExpiresAt,
		ResolutionMode:      resolved.ResolutionMode,
		MatchedMappingIDs:   resolved.MatchedMappingIDs,
		WGPubKey:            req.WGPubKey,
		SSHPubKey:           req.SSHPubKey,
		Hostname:            req.Hostname,
		DNSLabels:           req.DNSLabels,
		ExtraDNSLabels:      req.ExtraDNSLabels,
		ConnectionIP:        req.ConnectionIP,
	}
	// Under strict_priority the first matched mapping is the winning one
	// and is meaningful on its own. Under union every matched mapping
	// contributes auto_groups, so picking "the first" is arbitrary and
	// misleading in audit metadata — leave the field empty and rely on
	// MatchedMappingIDs for the full set.
	if resolved.ResolutionMode == string(types.MappingResolutionStrictPriority) && len(resolved.MatchedMappingIDs) > 0 {
		in.EntraDeviceMapping = resolved.MatchedMappingIDs[0]
	}
	result, err := m.PeerEnroller.EnrollEntraDevicePeer(ctx, in)
	if err != nil {
		if e, ok := AsError(err); ok {
			return nil, e
		}
		return nil, NewError(CodeInternal, "peer enrolment failed", err)
	}
	return result, nil
}

// issueBootstrapToken mints and persists a one-shot token the client can
// echo on its first gRPC Login to close the race window between enrolment
// and the WG-pubkey-based identity check.
func (m *Manager) issueBootstrapToken(ctx context.Context, peerID string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", NewError(CodeInternal, "failed to generate bootstrap token", err)
	}
	token := hex.EncodeToString(buf)
	if err := m.Store.StoreBootstrapToken(ctx, peerID, token); err != nil {
		return "", NewError(CodeInternal, "failed to persist bootstrap token", err)
	}
	return token, nil
}

// ValidateBootstrapToken is called by the gRPC Login path to verify the
// client's echoed bootstrap token.
func (m *Manager) ValidateBootstrapToken(ctx context.Context, peerID, token string) (bool, error) {
	if peerID == "" || token == "" {
		return false, nil
	}
	return m.Store.ConsumeBootstrapToken(ctx, peerID, token)
}
