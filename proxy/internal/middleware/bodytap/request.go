// Package bodytap owns the framework-side body capture used by the
// middleware chain. Request capture buffers up to N bytes of the
// request body for middleware inspection while replaying the original
// stream to the upstream. Response capture tees up to N bytes off the
// streaming response while every byte continues to flow to the client
// untouched.
//
// The package is the single owner of body access — middlewares never
// read req.Body or hijack the response writer. All inspection happens
// against the buffer surfaced by the tap, so streaming remains
// transparent to the client even when middlewares need access to the
// payload.
package bodytap

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// MaxRoutingScanBytes bounds how far ScanRoutingFields will read into a
// request body to recover routing fields when the normal capture is
// bypassed for size. Sized to comfortably hold a 1M-token context
// request (whose `model` field a client may place after a multi-MB
// `messages` array) while still capping pathological inputs.
const MaxRoutingScanBytes int64 = 32 << 20

// Request bypass reasons emitted as the `mw.capture.bypass_reason`
// metadata key by the chain when a request body is not surfaced.
const (
	BypassUpgradeHeader    = "upgrade_header"
	BypassConnectionUpgrd  = "connection_upgrade"
	BypassContentType      = "content_type_not_allowed"
	BypassBudget           = "capture_budget_exhausted"
	BypassNoConfig         = "no_capture_config"
	BypassNoMiddlewares    = "no_middlewares"
	BypassCapZero          = "cap_zero"
	BypassContentLengthCap = "content_length_over_cap"
)

// DefaultCaptureBudgetBytes is the default global capture-budget size.
const DefaultCaptureBudgetBytes int64 = 256 << 20

// Config holds per-target body capture limits after clamp validation.
// A zero MaxRequestBytes / MaxResponseBytes disables capture in that
// direction.
type Config struct {
	MaxRequestBytes  int64
	MaxResponseBytes int64
	ContentTypes     []string
}

// Budget is the global token-bucket semaphore shared across all
// in-flight captures so a single misbehaving target cannot exhaust the
// proxy.
type Budget interface {
	Acquire(n int64) bool
	Release(n int64)
}

// NewBudget returns a Budget with the given total byte cap. A zero or
// negative total disables the budget check.
func NewBudget(total int64) Budget {
	return &budget{total: total}
}

type budget struct {
	mu    sync.Mutex
	used  int64
	total int64
}

func (b *budget) Acquire(n int64) bool {
	if n <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total <= 0 {
		return true
	}
	if b.used+n > b.total {
		return false
	}
	b.used += n
	return true
}

func (b *budget) Release(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total <= 0 {
		return
	}
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
}

// CaptureRequest reads up to cfg.MaxRequestBytes from r.Body into a
// buffer suitable for middleware inspection, replacing r.Body with a
// replay reader so the upstream still sees the original bytes. When
// bypass != "" no body is read and r.Body is left untouched. The
// returned release function must be invoked once the request is fully
// processed; it returns the acquired budget tokens to the shared pool.
// release is always non-nil and is safe to defer immediately after the
// call.
func CaptureRequest(r *http.Request, cfg *Config, b Budget) (body []byte, truncated bool, originalSize int64, bypass string, release func(), err error) {
	release = func() {}
	if r == nil {
		return nil, false, 0, BypassNoConfig, release, nil
	}
	if cfg == nil {
		return nil, false, 0, BypassNoConfig, release, nil
	}
	if cfg.MaxRequestBytes <= 0 {
		return nil, false, 0, BypassCapZero, release, nil
	}
	if r.Header.Get("Upgrade") != "" {
		return nil, false, 0, BypassUpgradeHeader, release, nil
	}
	if strings.EqualFold(r.Header.Get("Connection"), "upgrade") {
		return nil, false, 0, BypassConnectionUpgrd, release, nil
	}
	if !contentTypeAllowed(r.Header.Get("Content-Type"), cfg.ContentTypes) {
		return nil, false, 0, BypassContentType, release, nil
	}

	originalSize = parseContentLength(r.Header.Get("Content-Length"))
	if originalSize > cfg.MaxRequestBytes {
		return nil, true, originalSize, BypassContentLengthCap, release, nil
	}

	limit := cfg.MaxRequestBytes
	if b != nil && !b.Acquire(limit) {
		return nil, false, originalSize, BypassBudget, release, nil
	}
	if b != nil {
		var released sync.Once
		release = func() {
			released.Do(func() { b.Release(limit) })
		}
	}

	if r.Body == nil || r.Body == http.NoBody {
		release()
		release = func() {}
		return nil, false, originalSize, "", release, nil
	}

	limited := io.LimitReader(r.Body, limit+1)
	buf, readErr := io.ReadAll(limited)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		release()
		release = func() {}
		return nil, false, originalSize, "", release, readErr
	}

	truncated = int64(len(buf)) > limit
	if truncated {
		replay := append([]byte(nil), buf...)
		viewable := buf[:limit]
		r.Body = &replayReadCloser{replay: bytes.NewReader(replay), tail: r.Body}
		return viewable, true, originalSize, "", release, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
	if originalSize <= 0 {
		originalSize = int64(len(buf))
	}
	return buf, false, originalSize, "", release, nil
}

// replayReadCloser replays the captured prefix and then forwards the
// remaining bytes from the original body so the upstream sees the
// full request stream even when capture truncates.
type replayReadCloser struct {
	replay  *bytes.Reader
	tail    io.ReadCloser
	drained bool
}

func (r *replayReadCloser) Read(p []byte) (int, error) {
	if !r.drained {
		n, err := r.replay.Read(p)
		if n > 0 {
			return n, nil
		}
		if errors.Is(err, io.EOF) {
			r.drained = true
		} else if err != nil {
			return 0, err
		}
	}
	return r.tail.Read(p)
}

func (r *replayReadCloser) Close() error {
	return r.tail.Close()
}

// ScanRoutingFields recovers the LLM routing fields ("model" and
// "stream") from a request whose normal capture was bypassed or
// truncated for size. It reads up to maxScan bytes of r.Body to locate
// the top-level keys — clients (e.g. Claude Code) may place `model`
// after a multi-MB `messages` array — then restores r.Body so the
// upstream still receives the full, untouched stream. Only the small
// routing fields are extracted; the prompt is never buffered for
// capture, keeping memory bounded. Returns ok=false when the body isn't
// a JSON object, the model field isn't found within maxScan, or on a
// read error.
func ScanRoutingFields(r *http.Request, maxScan int64) (model string, stream bool, ok bool) {
	if r == nil || r.Body == nil || r.Body == http.NoBody || maxScan <= 0 {
		return "", false, false
	}
	limited := io.LimitReader(r.Body, maxScan+1)
	buf, readErr := io.ReadAll(limited)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		// Mid-stream read error (e.g. client disconnect): restore the bytes
		// read so far plus the untouched tail and abort, rather than
		// forwarding only the partial prefix as if it were the whole body.
		r.Body = &replayReadCloser{replay: bytes.NewReader(append([]byte(nil), buf...)), tail: r.Body}
		return "", false, false
	}
	if int64(len(buf)) > maxScan {
		// Body exceeds the scan ceiling: restore the read prefix plus the
		// untouched tail so the upstream still gets every byte.
		r.Body = &replayReadCloser{replay: bytes.NewReader(append([]byte(nil), buf...)), tail: r.Body}
	} else {
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(buf))
	}
	return scanTopLevelModelStream(buf)
}

// scanTopLevelModelStream walks the top level of a JSON object via a
// streaming token reader, extracting the "model" string and "stream"
// bool without materialising large values (each non-target value is
// skipped as a RawMessage). Tolerant of truncation: returns whatever was
// found before a malformed/short tail.
func scanTopLevelModelStream(body []byte) (model string, stream bool, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return "", false, false
	}
	if d, isDelim := tok.(json.Delim); !isDelim || d != '{' {
		return "", false, false
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return model, stream, ok
		}
		key, _ := keyTok.(string)
		switch key {
		case "model":
			var v string
			if dec.Decode(&v) == nil {
				model, ok = v, true
			}
		case "stream":
			var v bool
			if dec.Decode(&v) == nil {
				stream = v
			}
		default:
			// Skip the value by walking tokens instead of decoding it into
			// a json.RawMessage — a multi-MB messages array would otherwise
			// be materialised in full just to be discarded.
			if err := skipValue(dec); err != nil {
				return model, stream, ok
			}
		}
	}
	return model, stream, ok
}

// skipValue consumes one JSON value from dec without materialising it.
// Scalars are a single token; objects/arrays are walked to their matching
// close delimiter so nested structures are skipped in bounded memory.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim || (d != '{' && d != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func contentTypeAllowed(ct string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	media := ct
	if idx := strings.Index(ct, ";"); idx >= 0 {
		media = ct[:idx]
	}
	media = strings.TrimSpace(strings.ToLower(media))
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), media) {
			return true
		}
	}
	return false
}

func parseContentLength(v string) int64 {
	if v == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}
