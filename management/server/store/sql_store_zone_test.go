package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_CreateZone(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})

	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	savedZone, err := store.GetZoneByID(context.Background(), LockingStrengthNone, accountID, zone.ID)
	require.NoError(t, err)
	require.NotNil(t, savedZone)
	assert.Equal(t, zone.ID, savedZone.ID)
	assert.Equal(t, zone.Name, savedZone.Name)
	assert.Equal(t, zone.Domain, savedZone.Domain)
	assert.Equal(t, zone.Enabled, savedZone.Enabled)
	assert.Equal(t, zone.EnableSearchDomain, savedZone.EnableSearchDomain)
	assert.Equal(t, zone.DistributionGroups, savedZone.DistributionGroups)
}

func TestSqlStore_GetZoneByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	tests := []struct {
		name        string
		accountID   string
		zoneID      string
		expectError bool
	}{
		{
			name:        "retrieve existing zone",
			accountID:   accountID,
			zoneID:      zone.ID,
			expectError: false,
		},
		{
			name:        "retrieve non-existing zone",
			accountID:   accountID,
			zoneID:      "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty zone ID",
			accountID:   accountID,
			zoneID:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			savedZone, err := store.GetZoneByID(context.Background(), LockingStrengthNone, tt.accountID, tt.zoneID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, savedZone)
			} else {
				require.NoError(t, err)
				require.NotNil(t, savedZone)
				assert.Equal(t, tt.zoneID, savedZone.ID)
			}
		})
	}
}

func TestSqlStore_GetAccountZones(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone1 := zones.NewZone(accountID, "Zone 1", "example1.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone1)
	require.NoError(t, err)

	zone2 := zones.NewZone(accountID, "Zone 2", "example2.com", true, true, []string{"group1", "group2"})
	err = store.CreateZone(context.Background(), zone2)
	require.NoError(t, err)

	allZones, err := store.GetAccountZones(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.NotNil(t, allZones)
	assert.GreaterOrEqual(t, len(allZones), 2)

	zoneIDs := make(map[string]bool)
	for _, z := range allZones {
		zoneIDs[z.ID] = true
	}
	assert.True(t, zoneIDs[zone1.ID])
	assert.True(t, zoneIDs[zone2.ID])
}

func TestSqlStore_GetZoneByDomain(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	otherAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3c"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	tests := []struct {
		name        string
		accountID   string
		domain      string
		expectError bool
		errorType   status.Type
	}{
		{
			name:        "retrieve existing zone by domain",
			accountID:   accountID,
			domain:      "example.com",
			expectError: false,
		},
		{
			name:        "retrieve non-existing zone domain",
			accountID:   accountID,
			domain:      "non-existing.com",
			expectError: true,
			errorType:   status.NotFound,
		},
		{
			name:        "retrieve with empty domain",
			accountID:   accountID,
			domain:      "",
			expectError: true,
			errorType:   status.NotFound,
		},
		{
			name:        "retrieve with different account ID",
			accountID:   otherAccountID,
			domain:      "example.com",
			expectError: true,
			errorType:   status.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			savedZone, err := store.GetZoneByDomain(context.Background(), tt.accountID, tt.domain)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tt.errorType, sErr.Type())
				require.Nil(t, savedZone)
			} else {
				require.NoError(t, err)
				require.NotNil(t, savedZone)
				assert.Equal(t, tt.domain, savedZone.Domain)
				assert.Equal(t, zone.ID, savedZone.ID)
				assert.Equal(t, zone.Name, savedZone.Name)
			}
		})
	}
}

func TestSqlStore_UpdateZone(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	zone.Name = "Updated Zone"
	zone.Domain = "updated.com"
	zone.Enabled = false
	zone.EnableSearchDomain = true
	zone.DistributionGroups = []string{"group2", "group3"}

	err = store.UpdateZone(context.Background(), zone)
	require.NoError(t, err)

	updatedZone, err := store.GetZoneByID(context.Background(), LockingStrengthNone, accountID, zone.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedZone)
	assert.Equal(t, "Updated Zone", updatedZone.Name)
	assert.Equal(t, "updated.com", updatedZone.Domain)
	assert.False(t, updatedZone.Enabled)
	assert.True(t, updatedZone.EnableSearchDomain)
	assert.Equal(t, []string{"group2", "group3"}, updatedZone.DistributionGroups)
}

func TestSqlStore_DeleteZone(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	err = store.DeleteZone(context.Background(), accountID, zone.ID)
	require.NoError(t, err)

	deletedZone, err := store.GetZoneByID(context.Background(), LockingStrengthNone, accountID, zone.ID)
	require.Error(t, err)
	require.Nil(t, deletedZone)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, sErr.Type(), status.NotFound)
}
