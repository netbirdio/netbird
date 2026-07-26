// Package modeldiscovery fetches and normalizes model catalogs from
// Agent Network provider endpoints. Discovery always runs on the proxy so
// it observes the same network path as inference traffic.
package modeldiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
)

const (
	SourceOpenAIV1Models = "openai_v1_models"
	SourceOllamaAPITags  = "ollama_api_tags"

	defaultTimeout      = 5 * time.Second
	maxResponseBytes    = 1 << 20 // 1 MiB, after HTTP decompression.
	maxUpstreamURLBytes = 4096
	maxHeaderNameBytes  = 256
	maxHeaderValueBytes = 64 << 10
	maxModels           = 500
	maxModelIDBytes     = 512
)

// Request contains the provider-owned values management resolved from the
// persisted provider record. Callers must not populate these fields from a
// dashboard-supplied URL or credential.
type Request struct {
	UpstreamURL         string
	AuthHeaderName      string
	AuthHeaderValue     string
	SkipTLSVerify       bool
	AllowOllamaFallback bool
}

// Model is the deliberately small response surface returned to management.
// Arbitrary fields supplied by an upstream never cross the control channel.
type Model struct {
	ID    string
	Label string
}

// Result is a normalized model catalog and the endpoint shape that supplied
// it.
type Result struct {
	Models []Model
	Source string
}

// Discoverer owns the HTTP client used for provider probes.
type Discoverer struct {
	client    *http.Client
	timeout   time.Duration
	bodyLimit int64
}

// New constructs a direct-upstream discoverer. The transport is the same
// host-network transport family used by Agent Network inference routes.
func New(logger *log.Logger) *Discoverer {
	return newWithTransport(roundtrip.NewDirectOnly(logger))
}

func newWithTransport(transport http.RoundTripper) *Discoverer {
	return &Discoverer{
		client: &http.Client{
			Transport: transport,
			// Redirects could move a credentialed request away from the
			// persisted provider origin. Discovery never follows them.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeout:   defaultTimeout,
		bodyLimit: maxResponseBytes,
	}
}

// Discover queries the OpenAI-compatible model-list endpoint. Ollama's native
// tags endpoint is attempted only when explicitly enabled and the primary
// endpoint reports that the route does not exist.
func (d *Discoverer) Discover(ctx context.Context, in Request) (Result, error) {
	if d == nil || d.client == nil {
		return Result{}, errors.New("model discovery client is unavailable")
	}
	if err := validateRequest(in); err != nil {
		return Result{}, err
	}

	timeout := d.timeout
	if timeout <= 0 || timeout > defaultTimeout {
		timeout = defaultTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	models, err := d.fetchOpenAIModels(probeCtx, in)
	if err == nil {
		return Result{Models: models, Source: SourceOpenAIV1Models}, nil
	}
	if !in.AllowOllamaFallback || !isMissingEndpoint(err) {
		return Result{}, err
	}

	models, err = d.fetchOllamaTags(probeCtx, in)
	if err != nil {
		return Result{}, err
	}
	return Result{Models: models, Source: SourceOllamaAPITags}, nil
}

func validateRequest(in Request) error {
	rawURL := strings.TrimSpace(in.UpstreamURL)
	if rawURL == "" {
		return errors.New("model discovery upstream URL is required")
	}
	if len(rawURL) > maxUpstreamURLBytes {
		return errors.New("model discovery upstream URL is too long")
	}
	if len(in.AuthHeaderName) > maxHeaderNameBytes || len(in.AuthHeaderValue) > maxHeaderValueBytes {
		return errors.New("model discovery authentication header is too large")
	}
	if (in.AuthHeaderName == "") != (in.AuthHeaderValue == "") {
		return errors.New("model discovery authentication header is incomplete")
	}
	if strings.ContainsAny(in.AuthHeaderName, "\r\n") || strings.ContainsAny(in.AuthHeaderValue, "\r\n") {
		return errors.New("model discovery authentication header is invalid")
	}
	if in.AuthHeaderName != "" && !strings.EqualFold(in.AuthHeaderName, "Authorization") {
		return errors.New("model discovery authentication header is unsupported")
	}
	return nil
}

func (d *Discoverer) fetchOpenAIModels(ctx context.Context, in Request) ([]Model, error) {
	body, err := d.fetch(ctx, in, "v1/models")
	if err != nil {
		return nil, err
	}

	var payload struct {
		Data *[]struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Data == nil {
		return nil, errors.New("upstream returned invalid OpenAI model-list JSON")
	}

	ids := make([]string, 0, len(*payload.Data))
	for _, model := range *payload.Data {
		ids = append(ids, model.ID)
	}
	return normalize(ids)
}

func (d *Discoverer) fetchOllamaTags(ctx context.Context, in Request) ([]Model, error) {
	body, err := d.fetch(ctx, in, "api/tags")
	if err != nil {
		return nil, err
	}

	var payload struct {
		Models *[]struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Models == nil {
		return nil, errors.New("upstream returned invalid Ollama tags JSON")
	}

	ids := make([]string, 0, len(*payload.Models))
	for _, model := range *payload.Models {
		id := model.Model
		if strings.TrimSpace(id) == "" {
			id = model.Name
		}
		ids = append(ids, id)
	}
	return normalize(ids)
}

func (d *Discoverer) fetch(ctx context.Context, in Request, endpointPath string) ([]byte, error) {
	endpoint, err := buildEndpointURL(in.UpstreamURL, endpointPath)
	if err != nil {
		return nil, err
	}

	reqCtx := roundtrip.WithDirectUpstream(ctx)
	if in.SkipTLSVerify {
		reqCtx = roundtrip.WithSkipTLSVerify(reqCtx)
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("create model discovery request")
	}
	req.Header.Set("Accept", "application/json")
	if in.AuthHeaderName != "" {
		// Phase 3 is Ollama-only. Canonicalizing the sole catalog-owned
		// credential header keeps the control message from becoming a generic
		// arbitrary-header primitive.
		req.Header.Set("Authorization", in.AuthHeaderValue)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("model discovery timed out")
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		// Deliberately omit the underlying error: net/http errors include the
		// internal URL, which should not be reflected through the public API.
		return nil, errors.New("model discovery request failed")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamStatusError{statusCode: resp.StatusCode}
	}

	limit := d.bodyLimit
	if limit <= 0 || limit > maxResponseBytes {
		limit = maxResponseBytes
	}
	if resp.ContentLength > limit {
		return nil, errors.New("model discovery response is too large")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("read model discovery response")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("model discovery response is too large")
	}
	return body, nil
}

func buildEndpointURL(rawURL, endpointPath string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return nil, errors.New("model discovery upstream URL is invalid")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		parsed.Scheme = "http"
	case "https":
		parsed.Scheme = "https"
	default:
		return nil, errors.New("model discovery upstream URL must use http or https")
	}
	if parsed.User != nil {
		return nil, errors.New("model discovery upstream URL must not contain credentials")
	}

	// Match Agent Network routing semantics: the static discovery path is
	// appended to any persisted base path. Queries and fragments on a provider
	// URL are not forwarded to inference and are likewise excluded here.
	parsed.Path = "/" + strings.TrimPrefix(path.Join(parsed.Path, endpointPath), "/")
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed, nil
}

func normalize(ids []string) ([]Model, error) {
	if len(ids) > maxModels {
		return nil, errors.New("upstream returned too many models")
	}

	seen := make(map[string]struct{}, len(ids))
	normalized := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if !validModelID(id) {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)

	models := make([]Model, 0, len(normalized))
	for _, id := range normalized {
		models = append(models, Model{ID: id, Label: id})
	}
	return models, nil
}

func validModelID(id string) bool {
	if id == "" || len(id) > maxModelIDBytes || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type upstreamStatusError struct {
	statusCode int
}

func (e *upstreamStatusError) Error() string {
	return fmt.Sprintf("upstream returned HTTP %d", e.statusCode)
}

func isMissingEndpoint(err error) bool {
	var statusErr *upstreamStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.statusCode == http.StatusNotFound || statusErr.statusCode == http.StatusMethodNotAllowed
}
