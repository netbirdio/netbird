package mdm

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// perInstallationKeys identify one network, or would collide between two
// installations. A named installation takes them only from its own policy key:
// the machine-wide managementURL would point it at another organisation's
// server, and a machine-wide preSharedKey would block every one of its peers.
var perInstallationKeys = map[string]struct{}{
	KeyManagementURL:       {},
	KeyPreSharedKey:        {},
	KeyWireguardPort:       {},
	KeyEnableLocalMetrics:  {},
	KeyLocalMetricsAddress: {},
}

// machineOnlyKeys can be set only machine-wide: an installation's own key
// cannot lift them.
var machineOnlyKeys = map[string]struct{}{
	KeyDisableNamedInstallations: {},
}

// InstallationPolicyFetcher is a PolicyFetcher that also supplies a named
// installation's own policy, as the per-installation registry key does.
type InstallationPolicyFetcher interface {
	FetchInstallation(name instance.Name) map[string]any
}

// withInstallationPolicy applies a named installation's view of the policy:
// the machine-wide posture values, without the per-installation ones,
// overridden by the installation's own key.
func (l *Loader) withInstallationPolicy(global map[string]any, name instance.Name) map[string]any {
	own, err := l.loadInstallation(name)
	if err != nil {
		log.Warnf("MDM policy of installation %s: %v", name, err)
	}
	return mergeInstallationPolicy(global, own)
}

func (l *Loader) loadInstallation(name instance.Name) (map[string]any, error) {
	if l.fetcher != nil {
		if f, ok := l.fetcher.(InstallationPolicyFetcher); ok {
			return f.FetchInstallation(name), nil
		}
		//nolint:nilnil // no per-installation source behind a plain fetcher
		return nil, nil
	}
	return loadInstallationPlatform(name)
}

func mergeInstallationPolicy(global, own map[string]any) map[string]any {
	if global == nil && own == nil {
		return nil
	}
	out := make(map[string]any, len(global)+len(own))
	for k, v := range global {
		if _, ok := perInstallationKeys[k]; !ok {
			out[k] = v
		}
	}
	for k, v := range own {
		if _, ok := machineOnlyKeys[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// NamedInstallationsDisabled reports whether the machine-wide policy forbids
// named installations. An unparseable value forbids them.
func (p *Policy) NamedInstallationsDisabled() bool {
	if !p.HasKey(KeyDisableNamedInstallations) {
		return false
	}
	disabled, ok := p.GetBool(KeyDisableNamedInstallations)
	return !ok || disabled
}
