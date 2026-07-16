package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidation(t *testing.T) {
	assert.NoError(t, ValidateSyncMessageVersion(nil))
	assert.NoError(t, ValidateSyncMessageVersion(toIntPtr(0)))
	assert.ErrorIs(t, ValidateSyncMessageVersion(toIntPtr(int(^uint(0)>>1))), ErrorUnrecognizedSyncMessageVersion)
	assert.ErrorIs(t, ValidateSyncMessageVersion(toIntPtr(-1)), ErrorUnrecognizedSyncMessageVersion)
}

func TestVersionFromConfig(t *testing.T) {
	assert.Equal(t, CurrentSyncMessageVersion, SyncMessageVersionFromConfig(nil))
	assert.Equal(t, CurrentSyncMessageVersion, SyncMessageVersionFromConfig(toIntPtr(1)))
	assert.Equal(t, Base, SyncMessageVersionFromConfig(toIntPtr(-1)))
	assert.Equal(t, Base, SyncMessageVersionFromConfig(toIntPtr(int(^uint(0)>>1))))
}

func TestPerAccountConversionStringToEnum(t *testing.T) {
	assert.Equal(t, map[string]SyncMessageVersion{"1": CurrentSyncMessageVersion}, SyncMessageVersionsFromMap(map[string]int{"1": 1}))
	assert.Equal(t, map[string]SyncMessageVersion{"2": Base}, SyncMessageVersionsFromMap(map[string]int{"2": -1}))
}

func TestCommonVersions(t *testing.T) {
	assert.Equal(t, Base, HighestCommonSyncMessageVersions(Base, CurrentSyncMessageVersion))
	assert.Equal(t, Base, HighestCommonSyncMessageVersions(CurrentSyncMessageVersion, Base))
	assert.Equal(t, CurrentSyncMessageVersion, HighestCommonSyncMessageVersions(CurrentSyncMessageVersion, CurrentSyncMessageVersion))
}

func toIntPtr(v int) *int {
	return &v
}
