package android

import (
	"github.com/netbirdio/netbird/client/mdm"
)

// PolicyFetcher is implemented by the native layer to return the current
// managed configuration as a JSON-encoded object string; "" means no MDM
// source is present.
type PolicyFetcher interface {
	FetchJSON() string
}

func loaderFor(p PolicyFetcher) *mdm.Loader {
	if p == nil {
		return mdm.NewJSONLoader(nil)
	}
	return mdm.NewJSONLoader(p.FetchJSON)
}
