package ebpf

import (
	"testing"
)

// featureFlagTest stands in for a second feature flag, so the set and unset
// paths can be exercised with more than the one flag the manager defines.
const featureFlagTest = 0b00000001

func TestManager_setFeatureFlag(t *testing.T) {
	mgr := GeneralManager{}
	mgr.setFeatureFlag(featureFlagTest)
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
	mgr.setFeatureFlag(featureFlagTest)
	mgr.setFeatureFlag(featureFlagDnsForwarder)

	err := mgr.unsetFeatureFlag(featureFlagTest)
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
