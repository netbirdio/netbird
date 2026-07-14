package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidation(t *testing.T) {
	assert.NoError(t, ValidateSyncMessageVersions([]string{"Base", "ComponentNetworkMap"}))
	assert.NoError(t, ValidateSyncMessageVersions([]string{}))
	assert.ErrorIs(t, ValidateSyncMessageVersions([]string{"Boom"}), ErrorUnrecognizedSyncMessageVersion)
	assert.ErrorIs(t, ValidateSyncMessageVersions([]string{"Base", "Boom"}), ErrorUnrecognizedSyncMessageVersion)
}

func TestConversionStringToEnum(t *testing.T) {
	assert.Equal(t, []SyncMessageVersion{0, 1}, SyncMessageVersionsFromString([]string{}))
	assert.Equal(t, []SyncMessageVersion{0}, SyncMessageVersionsFromString([]string{"Base"}))
	assert.Equal(t, []SyncMessageVersion{1}, SyncMessageVersionsFromString([]string{"ComponentNetworkMap"}))
}

func TestPerAccountConversionStringToEnum(t *testing.T) {
	assert.Equal(t, map[string][]SyncMessageVersion{"1": {0, 1}}, SyncMessageVersionsFromMap(map[string][]string{"1": {}}))
	assert.Equal(t, map[string][]SyncMessageVersion{"2": {0}}, SyncMessageVersionsFromMap(map[string][]string{"2": {"Base"}}))
	assert.Equal(t, map[string][]SyncMessageVersion{"3": {1}, "4": {0, 1}},
		SyncMessageVersionsFromMap(map[string][]string{
			"3": {"ComponentNetworkMap"},
			"4": {"Base", "ComponentNetworkMap"},
		}))
}

func TestConversionFromProtoEnums(t *testing.T) {
	assert.Equal(t, []SyncMessageVersion{}, SyncMessageVersionsFromProtoEnums([]int32{}))
	assert.Equal(t, []SyncMessageVersion{}, SyncMessageVersionsFromProtoEnums([]int32{0}))
	assert.Equal(t, []SyncMessageVersion{1}, SyncMessageVersionsFromProtoEnums([]int32{3}))
}

func TestCommonVersions(t *testing.T) {
	assert.Equal(t, []SyncMessageVersion{0},
		CommonSyncMessageVersions([]SyncMessageVersion{0, 1}, []SyncMessageVersion{}))
	assert.Equal(t, []SyncMessageVersion{0},
		CommonSyncMessageVersions([]SyncMessageVersion{0}, []SyncMessageVersion{0, 1, 2}))
	assert.Equal(t, []SyncMessageVersion{5, 1, 0},
		CommonSyncMessageVersions([]SyncMessageVersion{0, 1, 4, 5}, []SyncMessageVersion{1, 0, 5, 2}))
}
