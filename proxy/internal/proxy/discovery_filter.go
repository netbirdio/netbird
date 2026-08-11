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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBodyBytes+1))
	closeErr := resp.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(body) > maxDiscoveryBodyBytes {
		restoreBody(resp, body)
		return nil
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
		if _, ok := permitted[entryModelID(entry)]; ok {
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

// entryModelID returns the entry's model id in the form the policy stores
// it, or "" when the entry carries no usable id. A provider-prefixed id
// ("bedrock/anthropic.claude-sonnet-5") keeps only its last segment, which
// is what the operator registers.
func entryModelID(entry map[string]json.RawMessage) string {
	raw, ok := entry["id"]
	if !ok {
		return ""
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil {
		return ""
	}
	if slash := strings.LastIndex(id, "/"); slash >= 0 {
		id = id[slash+1:]
	}
	return sharedllm.NormalizeAnthropicModel(id)
}

// restoreBody puts body back on the response and fixes the length headers
// so the client reads exactly what is there.
func restoreBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
}
