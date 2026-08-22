package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	sharedllm "github.com/netbirdio/netbird/shared/llm"
)

// maxDiscoveryBodyBytes bounds the model-listing response the filter will
// buffer. A listing is a few kilobytes of ids; anything larger is not a
// listing we recognise, and buffering it to rewrite would cost more than
// the filtering is worth.
const maxDiscoveryBodyBytes = 1 << 20

// modelDiscoveryFilter returns a ModifyResponse hook that drops models the
// caller's policy does not authorise from a model-listing response, then
// delegates to next (which may be nil).
//
// Clients populate their model picker from this endpoint, so an unfiltered
// list offers models the very next request denies. The filter is
// best-effort: a response it cannot safely rewrite passes through
// untouched rather than reaching the client corrupted.
func modelDiscoveryFilter(allowed []string, next func(*http.Response) error) func(*http.Response) error {
	permitted := make(map[string]struct{}, len(allowed)*2)
	for _, id := range allowed {
		permitted[id] = struct{}{}
		permitted[sharedllm.NormalizeAnthropicModel(id)] = struct{}{}
	}

	return func(resp *http.Response) error {
		if err := filterModelListing(resp, permitted); err != nil {
			return err
		}
		if next == nil {
			return nil
		}
		return next(resp)
	}
}

// filterModelListing rewrites the response body in place, keeping only the
// entries whose id the policy authorises. Responses that are not a plain
// JSON listing are left alone.
func filterModelListing(resp *http.Response, permitted map[string]struct{}) error {
	if !isPlainJSONListing(resp) {
		return nil
	}

	// One byte past the cap, so an oversized body is detectable without
	// buffering all of it.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBodyBytes+1))
	if err != nil {
		_ = resp.Body.Close()
		return err
	}
	if len(body) > maxDiscoveryBodyBytes {
		// Too large to filter. Put the bytes already read back in front of the
		// unread remainder and forward the response exactly as the upstream
		// sent it, headers included. Buffering what was read and closing here
		// would truncate the body at the cap and hand the client a short,
		// invalid listing — worse than not filtering at all.
		resp.Body = spliceBody(body, resp.Body)
		return nil
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}

	filtered, ok := filterListingBody(body, permitted)
	if !ok {
		restoreBody(resp, body)
		return nil
	}
	restoreBody(resp, filtered)
	return nil
}

// isPlainJSONListing reports whether the response is a JSON body the filter
// can parse. A content-encoded body is skipped: the transport only
// transparently decompresses what it negotiated itself, and the client
// negotiates its own encoding on this request.
func isPlainJSONListing(resp *http.Response) bool {
	if resp == nil || resp.Body == nil {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json")
}

// filterListingBody returns the listing with unauthorised entries removed.
// ok is false when the body is not a listing shape, in which case the
// caller must forward the original bytes.
func filterListingBody(body []byte, permitted map[string]struct{}) ([]byte, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	raw, present := doc["data"]
	if !present {
		return nil, false
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, false
	}

	kept := make([]map[string]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		if entryPermitted(entry, permitted) {
			kept = append(kept, entry)
		}
	}

	encoded, err := json.Marshal(kept)
	if err != nil {
		return nil, false
	}
	doc["data"] = encoded
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

// entryPermitted reports whether a listing entry names a model the policy
// authorises, trying every form the same model is written in.
func entryPermitted(entry map[string]json.RawMessage, permitted map[string]struct{}) bool {
	raw, ok := entry["id"]
	if !ok {
		return false
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil {
		return false
	}
	for _, candidate := range modelIDForms(id) {
		if _, ok := permitted[candidate]; ok {
			return true
		}
	}
	return false
}

// modelIDForms returns the forms a single model id may be written in: the id
// itself, its undated form, and the same two with a gateway's provider
// prefix removed ("vertex_ai/claude-sonnet-5"). The bare id is tried first,
// because a self-hosted id can legitimately contain a slash of its own
// ("Qwen/Qwen2.5-0.5B-Instruct") and must not be cut down to its tail.
func modelIDForms(id string) []string {
	if id == "" {
		return nil
	}
	forms := []string{id, sharedllm.NormalizeAnthropicModel(id)}
	if slash := strings.LastIndex(id, "/"); slash >= 0 {
		tail := id[slash+1:]
		forms = append(forms, tail, sharedllm.NormalizeAnthropicModel(tail))
	}
	return forms
}

// restoreBody puts body back on the response and fixes the length headers
// so the client reads exactly what is there.
// spliceBody returns a ReadCloser that yields prefix followed by whatever is
// left in rest, closing rest when closed. It lets the filter put back bytes it
// consumed while deciding, without owning the rest of the stream.
func spliceBody(prefix []byte, rest io.ReadCloser) io.ReadCloser {
	return struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(bytes.NewReader(prefix), rest),
		Closer: rest,
	}
}

func restoreBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
}
