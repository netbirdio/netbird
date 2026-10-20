package mdm

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

type jsonPolicyFetcher struct {
	fetch func() string
}

// NewJSONLoader constructs a Loader whose policy source is a JSON-encoded
// object string, as produced by the mobile native layers; a nil fetch
// disables MDM enforcement.
func NewJSONLoader(fetch func() string) *Loader {
	if fetch == nil {
		return NewLoader(nil)
	}
	return NewLoader(&jsonPolicyFetcher{fetch: fetch})
}

func (f *jsonPolicyFetcher) Fetch() map[string]any {
	raw := f.fetch()
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
