package entra_device

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// PeerEnroller is the callback the Manager invokes after resolving a mapping
// to actually create the NetBird peer. In phase 1 this is wired to a
// closure that calls AccountManager.AddPeer. Keeping it as an interface
// avoids a hard dependency on the main AccountManager here.
type PeerEnroller interface {
	EnrollEntraDevicePeer(ctx context.Context, in EnrollPeerInput) (*EnrollPeerResult, error)
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
func (m *Manager) Enroll(ctx context.Context, req *EnrollRequest) (*EnrollResponse, error) {
	if req == nil {
		return nil, NewError(CodeInternal, "nil request", nil)
	}
	if req.TenantID == "" {
		return nil, NewError(CodeIntegrationNotFound, "tenant_id is required", nil)
	}

	// 1. Locate integration config by tenant.
	auth, err := m.Store.GetEntraDeviceAuthByTenant(ctx, req.TenantID)
	if err != nil {
		return nil, NewError(CodeInternal, "failed to load integration", err)
	}
	if auth == nil {
		return nil, NewError(CodeIntegrationNotFound,
			fmt.Sprintf("no Entra device auth integration is configured for tenant %s", req.TenantID), nil)
	}
	if !auth.Enabled {
		return nil, NewError(CodeIntegrationDisabled,
			"Entra device auth integration is disabled for this tenant", nil)
	}

	// 2. Consume nonce (single-use; this also ensures the nonce was issued by
	//    this server instance and has not yet expired).
	ok, err := m.NonceStore.Consume(strings.TrimSpace(req.Nonce))
	if err != nil {
		return nil, NewError(CodeInternal, "nonce store error", err)
	}
	if !ok {
		return nil, NewError(CodeInvalidNonce, "nonce is unknown, already consumed, or expired", nil)
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil {
		// Clients sometimes use the padded URL or Std alphabets. Fall back.
		if b, e2 := base64.StdEncoding.DecodeString(req.Nonce); e2 == nil {
			nonceBytes = b
		} else {
			return nil, NewError(CodeInvalidNonce, "nonce is not base64", err)
		}
	}

	// 3. Cert + proof-of-possession.
	identity, verr := m.Cert.Validate(req.CertChain, nonceBytes, req.NonceSignature)
	if verr != nil {
		return nil, verr
	}
	// Optional cross-check: if client supplied EntraDeviceID it must match.
	if req.EntraDeviceID != "" && !strings.EqualFold(req.EntraDeviceID, identity.EntraDeviceID) {
		return nil, NewError(CodeInvalidCertChain,
			fmt.Sprintf("device id mismatch: cert=%s, request=%s", identity.EntraDeviceID, req.EntraDeviceID), nil)
	}

	// 4. Graph: confirm device + collect groups (+ optional compliance).
	graph := m.NewGraph(auth.TenantID, auth.ClientID, auth.ClientSecret)

	device, gerr := graph.Device(ctx, identity.EntraDeviceID)
	if gerr != nil {
		return nil, NewError(CodeGroupLookupFailed,
			"graph device lookup failed", gerr)
	}
	if device == nil {
		return nil, NewError(CodeDeviceDisabled,
			"device not found in Entra; has it been deleted?", nil)
	}
	if !device.AccountEnabled {
		return nil, NewError(CodeDeviceDisabled,
			"device is disabled in Entra", nil)
	}
	identity.AccountEnabled = true

	groups, gerr := graph.TransitiveMemberOf(ctx, device.ID)
	if gerr != nil {
		return nil, NewError(CodeGroupLookupFailed,
			"graph transitiveMemberOf failed", gerr)
	}
	identity.GroupIDs = groups

	if auth.RequireIntuneCompliant {
		compliant, cerr := graph.IsCompliant(ctx, identity.EntraDeviceID)
		if cerr != nil {
			return nil, NewError(CodeGroupLookupFailed,
				"graph Intune compliance lookup failed", cerr)
		}
		if !compliant {
			return nil, NewError(CodeDeviceNotCompliant,
				"device is not compliant in Intune", nil)
		}
		identity.IsCompliant = true
	}

	// 5. Resolve the mapping.
	mappings, err := m.Store.ListEntraDeviceMappings(ctx, auth.AccountID)
	if err != nil {
		return nil, NewError(CodeInternal, "failed to list mappings", err)
	}
	resolved, verr := ResolveMapping(auth, mappings, identity.GroupIDs)
	if verr != nil {
		return nil, verr
	}

	// 6. Create the peer.
	if m.PeerEnroller == nil {
		return nil, NewError(CodeInternal, "server not configured to enroll peers", nil)
	}
	enrollIn := EnrollPeerInput{
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
	if len(resolved.MatchedMappingIDs) > 0 {
		enrollIn.EntraDeviceMapping = resolved.MatchedMappingIDs[0]
	}
	result, err := m.PeerEnroller.EnrollEntraDevicePeer(ctx, enrollIn)
	if err != nil {
		if e, ok := AsError(err); ok {
			return nil, e
		}
		return nil, NewError(CodeInternal, "peer enrolment failed", err)
	}

	// 7. Issue bootstrap token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, NewError(CodeInternal, "failed to generate bootstrap token", err)
	}
	token := hex.EncodeToString(tokenBytes)
	if err := m.Store.StoreBootstrapToken(ctx, result.PeerID, token); err != nil {
		return nil, NewError(CodeInternal, "failed to persist bootstrap token", err)
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

// ValidateBootstrapToken is called by the gRPC Login path to verify the
// client's echoed bootstrap token.
func (m *Manager) ValidateBootstrapToken(ctx context.Context, peerID, token string) (bool, error) {
	if peerID == "" || token == "" {
		return false, nil
	}
	return m.Store.ConsumeBootstrapToken(ctx, peerID, token)
}
