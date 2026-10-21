package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetPostureChecksByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name            string
		postureChecksID string
		expectError     bool
	}{
		{
			name:            "retrieve existing posture checks",
			postureChecksID: "csplshq7qv948l48f7t0",
			expectError:     false,
		},
		{
			name:            "retrieve non-existing posture checks",
			postureChecksID: "non-existing",
			expectError:     true,
		},
		{
			name:            "retrieve with empty posture checks ID",
			postureChecksID: "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			postureChecks, err := store.GetPostureChecksByID(context.Background(), LockingStrengthNone, accountID, tt.postureChecksID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, postureChecks)
			} else {
				require.NoError(t, err)
				require.NotNil(t, postureChecks)
				require.Equal(t, tt.postureChecksID, postureChecks.ID)
			}
		})
	}
}

func TestSqlStore_GetPostureChecksByIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name            string
		postureCheckIDs []string
		expectedCount   int
	}{
		{
			name:            "retrieve existing posture checks by existing IDs",
			postureCheckIDs: []string{"csplshq7qv948l48f7t0", "cspnllq7qv95uq1r4k90"},
			expectedCount:   2,
		},
		{
			name:            "empty posture check IDs list",
			postureCheckIDs: []string{},
			expectedCount:   0,
		},
		{
			name:            "non-existing posture check IDs",
			postureCheckIDs: []string{"nonexistent1", "nonexistent2"},
			expectedCount:   0,
		},
		{
			name:            "mixed existing and non-existing posture check IDs",
			postureCheckIDs: []string{"cspnllq7qv95uq1r4k90", "nonexistent"},
			expectedCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups, err := store.GetPostureChecksByIDs(context.Background(), LockingStrengthNone, accountID, tt.postureCheckIDs)
			require.NoError(t, err)
			require.Len(t, groups, tt.expectedCount)
		})
	}
}

func TestSqlStore_SavePostureChecks(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	postureChecks := &posture.Checks{
		ID:        "posture-checks-id",
		AccountID: accountID,
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.31.0",
			},
			OSVersionCheck: &posture.OSVersionCheck{
				Ios: &posture.MinVersionCheck{
					MinVersion: "13.0.1",
				},
				Linux: &posture.MinKernelVersionCheck{
					MinKernelVersion: "5.3.3-dev",
				},
			},
			GeoLocationCheck: &posture.GeoLocationCheck{
				Locations: []posture.Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
				Action: posture.CheckActionAllow,
			},
		},
	}
	err = store.SavePostureChecks(context.Background(), postureChecks)
	require.NoError(t, err)

	savePostureChecks, err := store.GetPostureChecksByID(context.Background(), LockingStrengthNone, accountID, "posture-checks-id")
	require.NoError(t, err)
	require.Equal(t, savePostureChecks, postureChecks)
}

func TestSqlStore_DeletePostureChecks(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name            string
		postureChecksID string
		expectError     bool
	}{
		{
			name:            "delete existing posture checks",
			postureChecksID: "csplshq7qv948l48f7t0",
			expectError:     false,
		},
		{
			name:            "delete non-existing posture checks",
			postureChecksID: "non-existing-posture-checks-id",
			expectError:     true,
		},
		{
			name:            "delete with empty posture checks ID",
			postureChecksID: "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = store.DeletePostureChecks(context.Background(), accountID, tt.postureChecksID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
			} else {
				require.NoError(t, err)
				group, err := store.GetPostureChecksByID(context.Background(), LockingStrengthNone, accountID, tt.postureChecksID)
				require.Error(t, err)
				require.Nil(t, group)
			}
		})
	}
}
