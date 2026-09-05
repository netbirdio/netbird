package ebpf

import (
	"testing"
)

func TestManager_setFeatureFlag(t *testing.T) {
	mgr := GeneralManager{}
	mgr.setFeatureFlag(featureFlagWGProxy)
	if mgr.featureFlags != featureFlagWGProxy {
		t.Errorf("invalid feature state")
	}

	mgr.setFeatureFlag(featureFlagWGProxy)
	if mgr.featureFlags != featureFlagWGProxy {
		t.Errorf("setting a flag twice must be idempotent, got: %d", mgr.featureFlags)
	}
}

func TestManager_unsetFeatureFlag(t *testing.T) {
	mgr := GeneralManager{}
	mgr.setFeatureFlag(featureFlagWGProxy)

	err := mgr.unsetFeatureFlag(featureFlagWGProxy)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if mgr.featureFlags != 0 {
		t.Errorf("invalid feature state, expected: %d, got: %d", 0, mgr.featureFlags)
	}
}
