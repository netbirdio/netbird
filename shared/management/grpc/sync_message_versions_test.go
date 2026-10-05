package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidation(t *testing.T) {
	assert.NoError(t, ValidateSyncMessageVersion(nil))
	assert.NoError(t, ValidateSyncMessageVersion(toIntPtr(0)))
	assert.NoError(t, ValidateSyncMessageVersion(toIntPtr(1)))
	assert.ErrorIs(t, ValidateSyncMessageVersion(toIntPtr(int(^uint(0)>>1))), ErrorUnrecognizedSyncMessageVersion)
	assert.ErrorIs(t, ValidateSyncMessageVersion(toIntPtr(-1)), ErrorUnrecognizedSyncMessageVersion)
}

func TestVersionFromConfig(t *testing.T) {
	assert.Equal(t, DefaultSyncMessageVersion, SyncMessageVersionFromConfig(nil))
	assert.Equal(t, Base, SyncMessageVersionFromConfig(toIntPtr(0)))
	assert.Equal(t, ComponentNetworkMap, SyncMessageVersionFromConfig(toIntPtr(1)))
	assert.Equal(t, DefaultSyncMessageVersion, SyncMessageVersionFromConfig(toIntPtr(-1)))
	assert.Equal(t, DefaultSyncMessageVersion, SyncMessageVersionFromConfig(toIntPtr(int(^uint(0)>>1))))
}

func TestPerAccountConversionStringToEnum(t *testing.T) {
	assert.Equal(t, map[string]SyncMessageVersion{"1": HighestSyncMessageVersion}, SyncMessageVersionsFromMap(map[string]int{"1": 1}))
	assert.Equal(t, map[string]SyncMessageVersion{"2": DefaultSyncMessageVersion}, SyncMessageVersionsFromMap(map[string]int{"2": -1}))
}

func TestCommonVersions(t *testing.T) {
	assert.Equal(t, Base, HighestCommonSyncMessageVersion(Base, HighestSyncMessageVersion))
	assert.Equal(t, Base, HighestCommonSyncMessageVersion(HighestSyncMessageVersion, Base))
	assert.Equal(t, Base, HighestCommonSyncMessageVersion(Base, Base))
	assert.Equal(t, HighestSyncMessageVersion, HighestCommonSyncMessageVersion(HighestSyncMessageVersion, HighestSyncMessageVersion))
}

func toIntPtr(v int) *int {
	return &v
}
