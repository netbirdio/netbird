package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_CreateDNSRecord(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	record := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.1", 300)

	err = store.CreateDNSRecord(context.Background(), record)
	require.NoError(t, err)

	savedRecord, err := store.GetDNSRecordByID(context.Background(), LockingStrengthNone, accountID, zone.ID, record.ID)
	require.NoError(t, err)
	require.NotNil(t, savedRecord)
	assert.Equal(t, record.ID, savedRecord.ID)
	assert.Equal(t, record.Name, savedRecord.Name)
	assert.Equal(t, record.Type, savedRecord.Type)
	assert.Equal(t, record.Content, savedRecord.Content)
	assert.Equal(t, record.TTL, savedRecord.TTL)
	assert.Equal(t, zone.ID, savedRecord.ZoneID)
}

func TestSqlStore_GetDNSRecordByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	record := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.1", 300)
	err = store.CreateDNSRecord(context.Background(), record)
	require.NoError(t, err)

	tests := []struct {
		name        string
		accountID   string
		zoneID      string
		recordID    string
		expectError bool
	}{
		{
			name:        "retrieve existing record",
			accountID:   accountID,
			zoneID:      zone.ID,
			recordID:    record.ID,
			expectError: false,
		},
		{
			name:        "retrieve non-existing record",
			accountID:   accountID,
			zoneID:      zone.ID,
			recordID:    "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty record ID",
			accountID:   accountID,
			zoneID:      zone.ID,
			recordID:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			savedRecord, err := store.GetDNSRecordByID(context.Background(), LockingStrengthNone, tt.accountID, tt.zoneID, tt.recordID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, savedRecord)
			} else {
				require.NoError(t, err)
				require.NotNil(t, savedRecord)
				assert.Equal(t, tt.recordID, savedRecord.ID)
			}
		})
	}
}

func TestSqlStore_GetZoneDNSRecords(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	recordA := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.1", 300)
	err = store.CreateDNSRecord(context.Background(), recordA)
	require.NoError(t, err)

	recordAAAA := records.NewRecord(accountID, zone.ID, "ipv6.example.com", records.RecordTypeAAAA, "2001:db8::1", 300)
	err = store.CreateDNSRecord(context.Background(), recordAAAA)
	require.NoError(t, err)

	recordCNAME := records.NewRecord(accountID, zone.ID, "alias.example.com", records.RecordTypeCNAME, "www.example.com", 300)
	err = store.CreateDNSRecord(context.Background(), recordCNAME)
	require.NoError(t, err)

	allRecords, err := store.GetZoneDNSRecords(context.Background(), LockingStrengthNone, accountID, zone.ID)
	require.NoError(t, err)
	require.NotNil(t, allRecords)
	assert.Equal(t, 3, len(allRecords))

	recordIDs := make(map[string]bool)
	for _, r := range allRecords {
		recordIDs[r.ID] = true
	}
	assert.True(t, recordIDs[recordA.ID])
	assert.True(t, recordIDs[recordAAAA.ID])
	assert.True(t, recordIDs[recordCNAME.ID])
}

func TestSqlStore_GetZoneDNSRecordsByName(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	record1 := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.1", 300)
	err = store.CreateDNSRecord(context.Background(), record1)
	require.NoError(t, err)

	record2 := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeAAAA, "2001:db8::1", 300)
	err = store.CreateDNSRecord(context.Background(), record2)
	require.NoError(t, err)

	record3 := records.NewRecord(accountID, zone.ID, "mail.example.com", records.RecordTypeA, "192.168.1.2", 600)
	err = store.CreateDNSRecord(context.Background(), record3)
	require.NoError(t, err)

	recordsByName, err := store.GetZoneDNSRecordsByName(context.Background(), LockingStrengthNone, accountID, zone.ID, "www.example.com")
	require.NoError(t, err)
	require.NotNil(t, recordsByName)
	assert.Equal(t, 2, len(recordsByName))

	for _, r := range recordsByName {
		assert.Equal(t, "www.example.com", r.Name)
	}
}

func TestSqlStore_UpdateDNSRecord(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	record := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.1", 300)
	err = store.CreateDNSRecord(context.Background(), record)
	require.NoError(t, err)

	record.Name = "api.example.com"
	record.Content = "192.168.1.100"
	record.TTL = 600

	err = store.UpdateDNSRecord(context.Background(), record)
	require.NoError(t, err)

	updatedRecord, err := store.GetDNSRecordByID(context.Background(), LockingStrengthNone, accountID, zone.ID, record.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedRecord)
	assert.Equal(t, "api.example.com", updatedRecord.Name)
	assert.Equal(t, "192.168.1.100", updatedRecord.Content)
	assert.Equal(t, 600, updatedRecord.TTL)
}

func TestSqlStore_DeleteDNSRecord(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	record := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.1", 300)
	err = store.CreateDNSRecord(context.Background(), record)
	require.NoError(t, err)

	err = store.DeleteDNSRecord(context.Background(), accountID, zone.ID, record.ID)
	require.NoError(t, err)

	deletedRecord, err := store.GetDNSRecordByID(context.Background(), LockingStrengthNone, accountID, zone.ID, record.ID)
	require.Error(t, err)
	require.Nil(t, deletedRecord)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, sErr.Type(), status.NotFound)
}

func TestSqlStore_DeleteZoneDNSRecords(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	zone := zones.NewZone(accountID, "Test Zone", "example.com", true, false, []string{"group1"})
	err = store.CreateZone(context.Background(), zone)
	require.NoError(t, err)

	record1 := records.NewRecord(accountID, zone.ID, "www.example.com", records.RecordTypeA, "192.168.1.1", 300)
	err = store.CreateDNSRecord(context.Background(), record1)
	require.NoError(t, err)

	record2 := records.NewRecord(accountID, zone.ID, "mail.example.com", records.RecordTypeA, "192.168.1.2", 600)
	err = store.CreateDNSRecord(context.Background(), record2)
	require.NoError(t, err)

	allRecords, err := store.GetZoneDNSRecords(context.Background(), LockingStrengthNone, accountID, zone.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, len(allRecords))

	err = store.DeleteZoneDNSRecords(context.Background(), accountID, zone.ID)
	require.NoError(t, err)

	remainingRecords, err := store.GetZoneDNSRecords(context.Background(), LockingStrengthNone, accountID, zone.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, len(remainingRecords))
}
