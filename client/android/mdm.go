//go:build android

package android

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

// PolicyFetcher is the mobile-side bridge for the MDM managed-config
// snapshot. The native layer (Kotlin) implements this and registers
// the instance per Client via Client.SetMDMPolicyFetcher. Every
// invocation of fetchJSON must read the current RestrictionsManager
// state and return the result as a JSON-encoded map[string]any string.
//
// JSON is used because gomobile does not support map[string]any
// crossing the JNI boundary — the adapter on the Go side parses the
// string back into the map[string]any expected by mdm.Loader.
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

// SetMDMPolicyFetcher registers the native-provided MDM policy fetcher
// on this Client. Call once from the gomobile-init code (Kotlin
// Application.onCreate or Service onCreate) before invoking Run /
// RunWithoutLogin. Passing nil disables MDM enforcement on this
// Client.
//
// The fetcher is held as a *mdm.Loader instance on the Client (no
// package-level state) — multiple Clients in the same process get
// independent Loaders, and tests can inject fakes per Client.
func (c *Client) SetMDMPolicyFetcher(p PolicyFetcher) {
	if p == nil {
		c.mdmLoader = mdm.NewLoader(nil)
		return
	}
	c.mdmLoader = mdm.NewLoader(&jsonFetcherAdapter{inner: p})
}

// applyMDMOverlay applies the Client-held MDM Loader's current policy
// on top of the just-read Config. Called immediately after every
// UpdateOrCreateConfig — profilemanager's apply() initialises the
// policy to empty and leaves overlay responsibility to the lifecycle
// owner. No-op when no fetcher was registered.
func (c *Client) applyMDMOverlay(cfg *profilemanager.Config) {
	if cfg == nil || c.mdmLoader == nil {
		return
	}
	cfg.ApplyMDMPolicy(c.mdmLoader.Load())
}
