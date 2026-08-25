//go:build android

package android

import (
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

// SetMDMPolicyFetcher registers the native-provided MDM policy fetcher on
// this Client; passing nil disables MDM enforcement.
func (c *Client) SetMDMPolicyFetcher(p PolicyFetcher) {
	c.mdmLoader = loaderFor(p)
	c.mdmDetector = mdm.NewChangeDetector(c.mdmLoader)
}

// HasMDMPolicyChanged re-reads the managed configuration and reports whether
// it changed since the last observation; call it from the native OS-change
// notification and restart the engine only on true.
func (c *Client) HasMDMPolicyChanged() bool {
	if c.mdmDetector == nil {
		return false
	}
	return c.mdmDetector.Changed()
}

// GetRestrictionsJSON returns the UI enforcement snapshot derived from the
// active MDM policy, in the JSON shape shared with the desktop frontend.
func (c *Client) GetRestrictionsJSON() (string, error) {
	return mdm.BuildRestrictions(c.mdmLoader.Load()).JSON()
}

func (c *Client) applyMDMOverlay(cfg *profilemanager.Config) {
	if cfg == nil || c.mdmLoader == nil {
		return
	}
	cfg.ApplyMDMPolicy(c.mdmLoader.Load())
}
