package entradevice

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// EnrolmentPathSuffix is the path under the management URL where the device
// enrolment endpoints live. Clients configured with a management URL ending
// in this path switch to the Entra enrolment flow instead of the regular
// gRPC login.
const EnrolmentPathSuffix = "/join/entra"

// DefaultTimeout caps individual HTTP calls to the challenge/enroll endpoints.
// It is intentionally generous (15s) because the server-side enrolment has to
// talk to Microsoft Graph, which can spike well above 1s under load.
const DefaultTimeout = 20 * time.Second

// Enroller drives the /challenge + /enroll HTTP round-trip.
type Enroller struct {
	// BaseURL is the management server base including scheme + host (and
	// optionally a port). Example: "https://mgmt.example.dk".
	//
	// The trailing /join/entra path is appended automatically; supplying it
	// yourself is tolerated.
	BaseURL string

	// HTTPClient is optional. If nil, a sensible default is used.
	HTTPClient *http.Client

	// Cert is the source of device identity (cert chain + signing key).
	Cert CertProvider

	// TenantID is the Entra tenant id the server has an integration for.
	// The server uses this to locate the EntraDeviceAuth row.
	TenantID string

	// Hostname is the preferred hostname to register the peer under. May be
	// empty; the server will fall back to "entra-<deviceID>".
	Hostname string

	// WGPubKey is the peer's WireGuard public key (base64). REQUIRED.
	WGPubKey string

	// SSHPubKey is optional — forwarded if non-empty.
	SSHPubKey string
}

// Enrol performs a single enrolment attempt. On success it returns the
// EntraEnrollState the caller should persist.
//
// Error handling: the returned error is a *Error when the server responded
// with a structured error body (so callers can branch on .Code), and a plain
// error for transport/cryptographic failures.
func (e *Enroller) Enrol(ctx context.Context) (*EntraEnrollState, error) {
	if e.Cert == nil {
		return nil, fmt.Errorf("enroller: Cert is required")
	}
	if e.TenantID == "" {
		return nil, fmt.Errorf("enroller: TenantID is required")
	}
	if e.WGPubKey == "" {
		return nil, fmt.Errorf("enroller: WGPubKey is required")
	}

	base := strings.TrimSuffix(strings.TrimRight(e.BaseURL, "/"), EnrolmentPathSuffix)
	client := e.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}

	// 1. /challenge
	challenge, err := e.fetchChallenge(ctx, client, base)
	if err != nil {
		return nil, err
	}

	// 2. Sign nonce
	rawNonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		// Server should always issue URL-safe base64, but accept std too.
		if b, e2 := base64.StdEncoding.DecodeString(challenge.Nonce); e2 == nil {
			rawNonce = b
		} else {
			return nil, fmt.Errorf("enroller: decode nonce: %w", err)
		}
	}
	sig, err := e.Cert.SignNonce(rawNonce)
	if err != nil {
		return nil, fmt.Errorf("enroller: sign nonce: %w", err)
	}

	// 3. Cert chain
	chain, err := e.Cert.CertChainDER()
	if err != nil {
		return nil, fmt.Errorf("enroller: cert chain: %w", err)
	}
	deviceID, err := e.Cert.DeviceID()
	if err != nil {
		return nil, fmt.Errorf("enroller: device id: %w", err)
	}

	// 4. /enroll
	body := enrollReq{
		TenantID:       e.TenantID,
		EntraDeviceID:  deviceID,
		CertChain:      EncodeChainB64(chain),
		Nonce:          challenge.Nonce,
		NonceSignature: base64.StdEncoding.EncodeToString(sig),
		WGPubKey:       e.WGPubKey,
		SSHPubKey:      e.SSHPubKey,
		Hostname:       e.Hostname,
	}
	resp, err := e.postEnroll(ctx, client, base, body)
	if err != nil {
		return nil, err
	}

	return &EntraEnrollState{
		EntraDeviceID:      deviceID,
		TenantID:           e.TenantID,
		PeerID:             resp.PeerID,
		EnrolledAt:         time.Now().UTC(),
		EnrolledViaURL:     base + EnrolmentPathSuffix,
		ResolutionMode:     resp.ResolutionMode,
		ResolvedAutoGroups: resp.ResolvedAutoGroups,
		MatchedMappingIDs:  resp.MatchedMappingIDs,
	}, nil
}

// --- internal ---

type challengeResp struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type enrollReq struct {
	TenantID       string   `json:"tenant_id"`
	EntraDeviceID  string   `json:"entra_device_id"`
	CertChain      []string `json:"cert_chain"`
	Nonce          string   `json:"nonce"`
	NonceSignature string   `json:"nonce_signature"`
	WGPubKey       string   `json:"wg_pub_key"`
	SSHPubKey      string   `json:"ssh_pub_key,omitempty"`
	Hostname       string   `json:"hostname,omitempty"`
}

type enrollResp struct {
	PeerID                   string   `json:"peer_id"`
	EnrollmentBootstrapToken string   `json:"enrollment_bootstrap_token"`
	ResolvedAutoGroups       []string `json:"resolved_auto_groups"`
	MatchedMappingIDs        []string `json:"matched_mapping_ids"`
	ResolutionMode           string   `json:"resolution_mode"`
}

func (e *Enroller) fetchChallenge(ctx context.Context, client *http.Client, base string) (*challengeResp, error) {
	u, err := url.JoinPath(base, EnrolmentPathSuffix, "challenge")
	if err != nil {
		return nil, fmt.Errorf("enroller: challenge url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("enroller: build challenge request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroller: challenge request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeServerError(resp.StatusCode, raw, "challenge")
	}
	var out challengeResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("enroller: decode challenge: %w", err)
	}
	if out.Nonce == "" {
		return nil, fmt.Errorf("enroller: challenge returned empty nonce")
	}
	return &out, nil
}

func (e *Enroller) postEnroll(ctx context.Context, client *http.Client, base string, body enrollReq) (*enrollResp, error) {
	u, err := url.JoinPath(base, EnrolmentPathSuffix, "enroll")
	if err != nil {
		return nil, fmt.Errorf("enroller: enroll url: %w", err)
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("enroller: marshal enroll body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("enroller: build enroll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroller: enroll request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, decodeServerError(resp.StatusCode, raw, "enroll")
	}
	var out enrollResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("enroller: decode enroll response: %w", err)
	}
	if out.PeerID == "" {
		return nil, fmt.Errorf("enroller: enroll response missing peer_id")
	}
	return &out, nil
}

// Error is a structured error returned when the server responded with a
// machine-readable error body (per docs/ENTRA_DEVICE_AUTH.md). Callers can
// branch on Code to surface specific messages in the UI / tray.
type Error struct {
	HTTPStatus int
	Stage      string
	Code       string
	Message    string
}

// Error implements error.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %d %s: %s", e.Stage, e.HTTPStatus, e.Code, e.Message)
}

type serverErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func decodeServerError(status int, raw []byte, stage string) error {
	var body serverErrorPayload
	if err := json.Unmarshal(raw, &body); err == nil && body.Code != "" {
		return &Error{HTTPStatus: status, Stage: stage, Code: body.Code, Message: body.Message}
	}
	return fmt.Errorf("enroller: %s returned %d: %s", stage, status, string(raw))
}
