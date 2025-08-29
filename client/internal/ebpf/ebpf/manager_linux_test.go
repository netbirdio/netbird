package ebpf

import (
	"testing"
)

func TestManager_setFeatureFlag(t *testing.T) {
	mgr := GeneralManager{}
	mgr.setFeatureFlag(featureFlagWGProxy)
	if mgr.featureFlags != 1 {
		t.Errorf("invalid feature state")
	}

	mgr.setFeatureFlag(featureFlagDnsForwarder)
	if mgr.featureFlags != 3 {
		t.Errorf("invalid feature state")
	}
}

func TestManager_unsetFeatureFlag(t *testing.T) {
	mgr := GeneralManager{}
	mgr.setFeatureFlag(featureFlagWGProxy)
	mgr.setFeatureFlag(featureFlagDnsForwarder)

	err := mgr.unsetFeatureFlag(featureFlagWGProxy)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if mgr.featureFlags != 2 {
		t.Errorf("invalid feature state, expected: %d, got: %d", 2, mgr.featureFlags)
	}

	err = mgr.unsetFeatureFlag(featureFlagDnsForwarder)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if mgr.featureFlags != 0 {
		t.Errorf("invalid feature state, expected: %d, got: %d", 0, mgr.featureFlags)
	}
}
