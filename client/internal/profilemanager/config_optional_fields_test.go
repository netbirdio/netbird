package profilemanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// optionalBoolFields lists the *bool fields of Config by name, derived from the
// type so a field added later is covered without touching these tests.
func optionalBoolFields() []string {
	pointerToBool := reflect.TypeOf((*bool)(nil))

	var fields []string
	configType := reflect.TypeOf(Config{})
	for i := range configType.NumField() {
		field := configType.Field(i)
		if field.Type == pointerToBool && field.Tag.Get("json") != "-" {
			fields = append(fields, field.Name)
		}
	}
	return fields
}

func requireNoUnsetOptionalBool(t *testing.T, config *Config, context string) {
	t.Helper()

	value := reflect.ValueOf(*config)
	for _, name := range optionalBoolFields() {
		require.False(t, value.FieldByName(name).IsNil(),
			"%s left %s unset, so its readers have to invent a default and a diff of it compares presence instead of value", context, name)
	}
}

// An optional bool must not be tristate. While one can be nil, true or false,
// every reader has to invent the meaning of nil, and — the reason this test
// exists — a diff of the config ends up comparing presence rather than value:
// that is what made the update-settings gate refuse `netbird up` for a client
// restating its own defaults. apply() is where a config becomes complete, so
// the invariant belongs to it: no *bool may come out of apply() unset.
func TestApplyLeavesNoOptionalBoolUnset(t *testing.T) {
	require.NotEmpty(t, optionalBoolFields(), "the invariant is only meaningful while Config has optional bools")

	t.Run("a config built from scratch", func(t *testing.T) {
		config := newConfigSkeleton()
		_, err := config.apply(ConfigInput{})
		require.NoError(t, err)

		requireNoUnsetOptionalBool(t, config, "apply on a new config")
	})

	t.Run("a config file that predates every optional field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "legacy.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"WgIface":"wt0"}`), 0o600))

		config, err := GetExistingConfig(path)
		require.NoError(t, err)

		requireNoUnsetOptionalBool(t, config, "a read of a legacy config")
	})

	t.Run("a config file that stores them as null", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "null.json")
		_, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: path})
		require.NoError(t, err)
		unsetOnDisk(t, path, optionalBoolFields()...)

		config, err := GetExistingConfig(path)
		require.NoError(t, err)

		requireNoUnsetOptionalBool(t, config, "a read of a config storing nulls")
	})
}

// The same invariant on disk: what a write leaves in the file is what the next
// client to read it starts from, so no write may store a null.
func TestNoWriteStoresAnUnsetOptionalBool(t *testing.T) {
	requireNoNullOnDisk := func(t *testing.T, path string, context string) {
		t.Helper()

		raw, err := os.ReadFile(path)
		require.NoError(t, err)

		var stored map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &stored))

		for _, name := range optionalBoolFields() {
			value, present := stored[name]
			require.True(t, present, "%s did not store %s at all", context, name)
			require.NotEqual(t, "null", string(value), "%s stored %s as null", context, name)
		}
	}

	t.Run("UpdateOrCreateConfig", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "created.json")
		_, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: path, ManagementURL: DefaultManagementURL})
		require.NoError(t, err)

		requireNoNullOnDisk(t, path, "UpdateOrCreateConfig")
	})

	t.Run("UpdateConfig over a config storing nulls", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "stored.json")
		_, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: path})
		require.NoError(t, err)
		unsetOnDisk(t, path, optionalBoolFields()...)

		_, err = UpdateConfig(ConfigInput{ConfigPath: path, ManagementURL: "https://mgmt.example.com"})
		require.NoError(t, err)

		requireNoNullOnDisk(t, path, "UpdateConfig")
	})

	// Renaming used to copy the file back through a bare Unmarshal, which
	// preserved the nulls a pre-fix client had written.
	t.Run("RenameProfile", func(t *testing.T) {
		withTestSM(t, func(sm *ServiceManager, username string) {
			created, err := sm.AddProfile("work", username)
			require.NoError(t, err)
			unsetOnDisk(t, created.Path, optionalBoolFields()...)

			require.NoError(t, sm.RenameProfile(created.ID, username, "office"))

			requireNoNullOnDisk(t, created.Path, "RenameProfile")
		})
	})
}
