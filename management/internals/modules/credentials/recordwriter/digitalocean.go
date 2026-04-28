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
)

const digitalOceanAPIBase = "https://api.digitalocean.com/v2"

// digitalOceanWriter implements RecordWriter against DigitalOcean's REST
// API. We hit the API directly rather than depending on godo because the
// DO SDK is not in go.mod and pulling it in for four endpoints (get
// domain, list records, create record, delete record) would expand the
// transitive surface significantly. Cloudflare's writer takes the same
// approach for the same reasons.
type digitalOceanWriter struct {
	authToken  string
	httpClient *http.Client
}

func init() {
	registerRecordWriter("digitalocean", buildDigitalOceanWriter)
}

// buildDigitalOceanWriter constructs a DigitalOcean writer from a
// credential field map. Required field: "auth_token" — a personal access
// token with at least write scope on the target domain. The field name
// matches provider_digitalocean.go in the cert path so a single saved
// credential works in both the cert path and the auto-configure path.
func buildDigitalOceanWriter(secret map[string]string) (RecordWriter, error) {
	token := secret["auth_token"]
	if token == "" {
		return nil, fmt.Errorf("digitalocean credential is missing required field %q", "auth_token")
	}
	return &digitalOceanWriter{
		authToken:  token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// doDomain is the shape DO returns from GET /v2/domains/{name}.
type doDomain struct {
	Name string `json:"name"`
	TTL  int    `json:"ttl"`
}

type doDomainEnvelope struct {
	Domain doDomain `json:"domain"`
}

// doRecord matches the fields we care about on DO's domain_record object.
// DO stores record names relative to the zone — a CNAME at
// "*.app.example.com" in zone "example.com" has Name "*.app".
type doRecord struct {
	ID   int    `json:"id,omitempty"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl,omitempty"`
}

type doRecordsEnvelope struct {
	DomainRecords []doRecord `json:"domain_records"`
}

// doErrorEnvelope is DO's error body. We don't currently branch on Id but
// we capture it to make debugging easier when an unexpected error code
// surfaces.
type doErrorEnvelope struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

func (w *digitalOceanWriter) WriteCNAME(ctx context.Context, fqdn, target string, ttl int) error {
	zone, err := w.findZone(ctx, fqdn)
	if err != nil {
		return err
	}

	existing, err := w.findCNAME(ctx, zone, fqdn)
	if err != nil {
		return err
	}
	if existing != nil {
		if normalizeDOTarget(existing.Data) == normalizeDOTarget(target) {
			return nil // idempotent: same target already in place
		}
		return ErrRecordExists
	}

	rec := doRecord{
		Type: "CNAME",
		Name: relativizeName(fqdn, zone),
		Data: target,
		TTL:  ttl,
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal digitalocean record: %w", err)
	}

	resp, err := w.do(ctx, http.MethodPost,
		fmt.Sprintf("%s/domains/%s/records", digitalOceanAPIBase, url.PathEscape(zone)),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return w.checkStatus(resp)
}

func (w *digitalOceanWriter) DeleteCNAME(ctx context.Context, fqdn string) error {
	zone, err := w.findZone(ctx, fqdn)
	if err != nil {
		if errors.Is(err, ErrZoneNotFound) {
			return nil // missing zone → missing record → success
		}
		return err
	}

	existing, err := w.findCNAME(ctx, zone, fqdn)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil // already absent
	}

	resp, err := w.do(ctx, http.MethodDelete,
		fmt.Sprintf("%s/domains/%s/records/%d", digitalOceanAPIBase, url.PathEscape(zone), existing.ID),
		nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return w.checkStatus(resp)
}

// findZone iterates apex candidates longest-first and returns the first
// one DO reports as belonging to this account. Returns ErrZoneNotFound
// if every candidate 404s.
func (w *digitalOceanWriter) findZone(ctx context.Context, fqdn string) (string, error) {
	for _, candidate := range apexCandidates(fqdn) {
		u := fmt.Sprintf("%s/domains/%s", digitalOceanAPIBase, url.PathEscape(candidate))
		resp, err := w.do(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		// Drain & close before we consider the next candidate.
		switch {
		case resp.StatusCode == http.StatusOK:
			var env doDomainEnvelope
			if err := decodeJSON(resp, &env); err != nil {
				return "", err
			}
			return candidate, nil
		case resp.StatusCode == http.StatusNotFound:
			resp.Body.Close()
			continue
		default:
			err := mapStatus(resp)
			resp.Body.Close()
			if err != nil {
				return "", err
			}
			// Unexpected status without a sentinel — treat as unavailable.
			return "", fmt.Errorf("%w: unexpected status %d on domain lookup", ErrProviderUnavailable, resp.StatusCode)
		}
	}
	return "", ErrZoneNotFound
}

// findCNAME returns the existing CNAME record at fqdn within zone, or nil
// if none. Returns an error only on transport/auth failures.
func (w *digitalOceanWriter) findCNAME(ctx context.Context, zone, fqdn string) (*doRecord, error) {
	// DO's name filter expects the relative form. We also append per_page
	// to keep things in a single page for typical zones.
	rel := relativizeName(fqdn, zone)
	q := url.Values{}
	q.Set("name", rel)
	q.Set("type", "CNAME")
	q.Set("per_page", "200")

	u := fmt.Sprintf("%s/domains/%s/records?%s",
		digitalOceanAPIBase, url.PathEscape(zone), q.Encode())
	resp, err := w.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrZoneNotFound
	}
	if err := mapStatus(resp); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d on record list", ErrProviderUnavailable, resp.StatusCode)
	}

	var env doRecordsEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode digitalocean record list: %w", err)
	}

	// DO's name filter is reportedly not exact across all SDKs/clients —
	// reconfirm by reconstructing the absolute name and matching against
	// fqdn. This also lets us tolerate either form being returned.
	wantRel := rel
	wantAbs := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	for i := range env.DomainRecords {
		r := &env.DomainRecords[i]
		if !strings.EqualFold(r.Type, "CNAME") {
			continue
		}
		if matchesName(r.Name, wantRel, wantAbs, zone) {
			return r, nil
		}
	}
	return nil, nil
}

// matchesName checks whether a DO-reported record name corresponds to the
// FQDN we asked about. DO usually returns the relative form ("*.app" for
// "*.app.example.com" in zone "example.com"), but we tolerate the
// absolute form too.
func matchesName(got, wantRel, wantAbs, zone string) bool {
	got = strings.TrimSuffix(strings.ToLower(got), ".")
	wantRel = strings.ToLower(wantRel)
	wantAbs = strings.ToLower(wantAbs)
	zone = strings.ToLower(zone)
	if got == wantRel {
		return true
	}
	if got == wantAbs {
		return true
	}
	// "@" represents the apex itself.
	if got == "@" && wantAbs == zone {
		return true
	}
	// Reconstruct absolute from relative.
	if got != "" && got+"."+zone == wantAbs {
		return true
	}
	return false
}

// relativizeName strips the zone suffix from fqdn so the name field DO
// expects in create requests is correct. If fqdn equals zone, returns
// "@" (DO's apex marker).
func relativizeName(fqdn, zone string) string {
	host := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if host == zone {
		return "@"
	}
	suffix := "." + zone
	if strings.HasSuffix(host, suffix) {
		return host[:len(host)-len(suffix)]
	}
	// Caller passed a name that doesn't sit under zone — fall back to the
	// host as given. Should not happen given findZone's invariants.
	return host
}

func (w *digitalOceanWriter) do(ctx context.Context, method, urlStr string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("build digitalocean request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return resp, nil
}

// checkStatus is used for write/delete responses where we don't need the
// body. 200, 201, 204 are all success; anything else maps via mapStatus
// or surfaces the body for diagnostics.
func (w *digitalOceanWriter) checkStatus(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent, http.StatusAccepted:
		return nil
	}
	if err := mapStatus(resp); err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e doErrorEnvelope
	_ = json.Unmarshal(body, &e)
	if e.Message != "" {
		return fmt.Errorf("digitalocean API error: %s (%s)", e.Message, e.ID)
	}
	return fmt.Errorf("digitalocean API error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// mapStatus translates HTTP status codes shared across DO endpoints into
// the package's sentinel errors. Returns nil if the status is not a
// known failure (caller decides whether 200 or 404 is expected for its
// endpoint).
func mapStatus(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		return ErrInsufficientScope
	case resp.StatusCode == http.StatusTooManyRequests:
		return ErrProviderRateLimited
	case resp.StatusCode >= 500:
		return ErrProviderUnavailable
	}
	return nil
}

// decodeJSON reads & closes the response body, decoding into out. Used
// for endpoints where a 200 OK is the only success and we need the body.
func decodeJSON(resp *http.Response, out interface{}) error {
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode digitalocean response: %w", err)
	}
	return nil
}

// normalizeDOTarget strips a trailing dot and lower-cases for comparison.
// DO returns CNAME data with a trailing dot ("target.example.com."); we
// store the user-provided form without it. Defined locally to avoid
// depending on cloudflare.go's unexported helper.
func normalizeDOTarget(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}
