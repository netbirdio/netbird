//go:build android

package android

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/mdm"
)

// PolicyFetcher is the mobile-side bridge for the MDM managed-config
// snapshot. The native layer (Kotlin) implements this and registers
// the instance via SetMobilePolicyFetcher at app start. Every
// invocation must read the current RestrictionsManager state and
// return the result as a JSON-encoded map[string]any string.
//
// JSON is used because gomobile does not support map[string]any
// crossing the JNI boundary — the adapter on the Go side parses the
// string back into the map[string]any expected by mdm.LoadPolicy.
//
// Return value contract:
//   - "" (empty)         : interpreted as "no MDM source / no managed keys"
//   - "{}"               : managed config explicitly empty
//   - "{...}"            : JSON object with key/value pairs
//   - malformed JSON     : logged and treated as empty
type PolicyFetcher interface {
	FetchJSON() string
}

// jsonFetcherAdapter wraps a gomobile-exposed PolicyFetcher into the
// internal mdm.PolicyFetcher interface, taking care of JSON decoding
// on every Fetch.
type jsonFetcherAdapter struct {
	inner PolicyFetcher
}

func (a *jsonFetcherAdapter) Fetch() map[string]any {
	raw := a.inner.FetchJSON()
	if raw == "" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		log.Warnf("MDM mobile fetcher: invalid JSON payload from native: %v", err)
		return nil
	}
	return out
}

// SetMobilePolicyFetcher registers the native-provided MDM policy
// fetcher. Call exactly once from the gomobile-init code (Kotlin
// Application.onCreate) before the daemon starts. Passing nil
// effectively disables MDM enforcement on this build.
func SetMobilePolicyFetcher(p PolicyFetcher) {
	if p == nil {
		mdm.SetMobilePolicyFetcher(nil)
		return
	}
	mdm.SetMobilePolicyFetcher(&jsonFetcherAdapter{inner: p})
}
