package recordwriter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/modules/credentials/secretpayload"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cloudflareWriter implements RecordWriter against Cloudflare's REST API.
// We hit the API directly rather than depending on cloudflare-go because
// (a) Lego's existing Cloudflare path uses an internal HTTP client too
// — there's no shared client to reuse, and (b) avoiding the cloudflare-go
// dependency keeps go.mod lean (its surface is large and most of it is
// unrelated to DNS).
type cloudflareWriter struct {
	authToken  string
	httpClient *http.Client
}

func init() {
	registerRecordWriter("cloudflare", buildCloudflareWriter)
}

// buildCloudflareWriter constructs a Cloudflare writer from a credential
// field map. Required field: "auth_token". Falls back to secretpayload's
// LegacyKey to support older plain-string Cloudflare credentials —
// matching provider_cloudflare.go's behavior so a single saved credential
// works in both the cert path and the auto-configure path.
func buildCloudflareWriter(secret map[string]string) (RecordWriter, error) {
	token := secret["auth_token"]
	if token == "" {
		token = secret[secretpayload.LegacyKey]
	}
	if token == "" {
		return nil, fmt.Errorf("cloudflare credential is missing required field %q", "auth_token")
	}
	return &cloudflareWriter{
		authToken:  token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// cloudflareEnvelope is the shape Cloudflare wraps every response in.
// We capture both success and error data so we can map response statuses
// to sentinel errors precisely.
type cloudflareEnvelope struct {
	Success bool                `json:"success"`
	Errors  []cloudflareAPIErr  `json:"errors"`
	Result  json.RawMessage     `json:"result"`
}

type cloudflareAPIErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cloudflareDNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

func (w *cloudflareWriter) WriteCNAME(ctx context.Context, fqdn, target string, ttl int) error {
	zoneID, err := w.findZoneID(ctx, fqdn)
	if err != nil {
		return err
	}

	existing, err := w.findCNAME(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	if existing != nil {
		if normalizeCNAMETarget(existing.Content) == normalizeCNAMETarget(target) {
			return nil // idempotent: same target already in place
		}
		return ErrRecordExists
	}

	rec := cloudflareDNSRecord{Type: "CNAME", Name: fqdn, Content: target, TTL: ttl}
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal cloudflare record: %w", err)
	}

	resp, err := w.do(ctx, http.MethodPost,
		fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, zoneID),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return w.checkEnvelope(resp)
}

func (w *cloudflareWriter) DeleteCNAME(ctx context.Context, fqdn string) error {
	zoneID, err := w.findZoneID(ctx, fqdn)
	if err != nil {
		if errors.Is(err, ErrZoneNotFound) {
			return nil // missing zone → missing record → success
		}
		return err
	}

	existing, err := w.findCNAME(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil // already absent
	}

	resp, err := w.do(ctx, http.MethodDelete,
		fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, zoneID, existing.ID),
		nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return w.checkEnvelope(resp)
}

// findZoneID iterates apex candidates longest-first and returns the
// zone ID for the first one Cloudflare reports as belonging to this
// account. Returns ErrZoneNotFound if none match.
func (w *cloudflareWriter) findZoneID(ctx context.Context, fqdn string) (string, error) {
	for _, candidate := range apexCandidates(fqdn) {
		u := fmt.Sprintf("%s/zones?name=%s", cloudflareAPIBase, url.QueryEscape(candidate))
		resp, err := w.do(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		env, err := w.parseEnvelope(resp)
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		var zones []cloudflareZone
		if err := json.Unmarshal(env.Result, &zones); err != nil {
			return "", fmt.Errorf("decode cloudflare zone list: %w", err)
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", ErrZoneNotFound
}

// findCNAME returns the existing CNAME record at fqdn in the given zone,
// or nil if none exists. Returns an error only on transport/auth failures.
func (w *cloudflareWriter) findCNAME(ctx context.Context, zoneID, fqdn string) (*cloudflareDNSRecord, error) {
	u := fmt.Sprintf("%s/zones/%s/dns_records?type=CNAME&name=%s",
		cloudflareAPIBase, zoneID, url.QueryEscape(fqdn))
	resp, err := w.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	env, err := w.parseEnvelope(resp)
	if err != nil {
		return nil, err
	}
	var records []cloudflareDNSRecord
	if err := json.Unmarshal(env.Result, &records); err != nil {
		return nil, fmt.Errorf("decode cloudflare record list: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
}

func (w *cloudflareWriter) do(ctx context.Context, method, urlStr string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("build cloudflare request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.authToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return resp, nil
}

// parseEnvelope decodes a Cloudflare response and translates HTTP/auth
// failures into sentinel errors. Returns the envelope on success so the
// caller can decode Result into a typed value.
func (w *cloudflareWriter) parseEnvelope(resp *http.Response) (*cloudflareEnvelope, error) {
	switch {
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		return nil, ErrInsufficientScope
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrProviderRateLimited
	case resp.StatusCode >= 500:
		return nil, ErrProviderUnavailable
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read cloudflare response: %w", err)
	}
	var env cloudflareEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode cloudflare envelope: %w", err)
	}
	if !env.Success {
		// Inspect Cloudflare's own error codes for finer mapping.
		// 9103/9109 = invalid auth, 6003 = invalid request body, 7000
		// range = various permission errors. Default to InsufficientScope
		// when we can't classify confidently — most user-visible failures
		// at this layer are auth/scope.
		for _, e := range env.Errors {
			if e.Code == 9103 || e.Code == 9109 || (e.Code >= 7000 && e.Code < 8000) {
				return nil, ErrInsufficientScope
			}
		}
		return nil, fmt.Errorf("cloudflare API error: %s", formatCloudflareErrors(env.Errors))
	}
	return &env, nil
}

// checkEnvelope is parseEnvelope where we only care about success/failure,
// not the result body. Used for write/delete calls.
func (w *cloudflareWriter) checkEnvelope(resp *http.Response) error {
	_, err := w.parseEnvelope(resp)
	return err
}

func formatCloudflareErrors(errs []cloudflareAPIErr) string {
	if len(errs) == 0 {
		return "unspecified"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%d %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

// normalizeCNAMETarget strips a single trailing dot for comparison. DNS
// CNAME values are equivalent whether stored as "x.example.com" or
// "x.example.com." — Cloudflare returns them without the dot, but defending
// against either form costs nothing.
func normalizeCNAMETarget(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}
