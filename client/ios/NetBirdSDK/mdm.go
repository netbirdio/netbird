//go:build ios

package NetBirdSDK

import (
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

// PolicyFetcher is implemented by the native layer to return the current
// managed configuration as a JSON-encoded object string; "" means no MDM
// source is present.
type PolicyFetcher interface {
	FetchJSON() string
}

type mdmSource struct {
	loader   *mdm.Loader
	detector *mdm.ChangeDetector
}

// SetMDMPolicyFetcher registers the native-provided MDM policy fetcher on
// this Client; passing nil disables MDM enforcement.
func (c *Client) SetMDMPolicyFetcher(p PolicyFetcher) {
	loader := loaderFor(p)
	c.mdmSource.Store(&mdmSource{loader: loader, detector: mdm.NewChangeDetector(loader)})
}

// HasMDMPolicyChanged re-reads the managed configuration and reports whether
// it changed since the last observation; call it from the native OS-change
// notification and restart the engine only on true.
func (c *Client) HasMDMPolicyChanged() bool {
	src := c.mdmSource.Load()
	if src == nil {
		return false
	}
	return src.detector.Changed()
}

// GetRestrictionsJSON returns the UI enforcement snapshot derived from the
// active MDM policy, in the JSON shape shared with the desktop frontend.
func (c *Client) GetRestrictionsJSON() (string, error) {
	return mdm.BuildRestrictions(c.mdmLoader().Load()).JSON()
}

func (c *Client) applyMDMOverlay(cfg *profilemanager.Config) {
	loader := c.mdmLoader()
	if cfg == nil || loader == nil {
		return
	}
	cfg.ApplyMDMPolicy(loader.Load())
}

func (c *Client) mdmLoader() *mdm.Loader {
	if src := c.mdmSource.Load(); src != nil {
		return src.loader
	}
	return nil
}

func loaderFor(p PolicyFetcher) *mdm.Loader {
	if p == nil {
		return mdm.NewJSONLoader(nil)
	}
	return mdm.NewJSONLoader(p.FetchJSON)
}
