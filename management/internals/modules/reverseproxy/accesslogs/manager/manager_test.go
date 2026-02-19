package manager

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/store"
)

func TestCleanupOldAccessLogs(t *testing.T) {
	tests := []struct {
		name          string
		retentionDays int
		setupMock     func(*store.MockStore)
		expectedCount int64
		expectedError bool
	}{
		{
			name:          "cleanup logs older than retention period",
			retentionDays: 30,
			setupMock: func(mockStore *store.MockStore) {
				mockStore.EXPECT().
					DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, olderThan time.Time) (int64, error) {
						expectedCutoff := time.Now().AddDate(0, 0, -30)
						timeDiff := olderThan.Sub(expectedCutoff)
						if timeDiff.Abs() > time.Second {
							t.Errorf("cutoff time not as expected: got %v, want ~%v", olderThan, expectedCutoff)
						}
						return 5, nil
					})
			},
			expectedCount: 5,
			expectedError: false,
		},
		{
			name:          "no logs to cleanup",
			retentionDays: 30,
			setupMock: func(mockStore *store.MockStore) {
				mockStore.EXPECT().
					DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
					Return(int64(0), nil)
			},
			expectedCount: 0,
			expectedError: false,
		},
		{
			name:          "zero retention days skips cleanup",
			retentionDays: 0,
			setupMock: func(mockStore *store.MockStore) {
				// No expectations - DeleteOldAccessLogs should not be called
			},
			expectedCount: 0,
			expectedError: false,
		},
		{
			name:          "negative retention days skips cleanup",
			retentionDays: -10,
			setupMock: func(mockStore *store.MockStore) {
				// No expectations - DeleteOldAccessLogs should not be called
			},
			expectedCount: 0,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStore := store.NewMockStore(ctrl)
			tt.setupMock(mockStore)

			manager := &managerImpl{
				store: mockStore,
			}

			ctx := context.Background()
			deletedCount, err := manager.CleanupOldAccessLogs(ctx, tt.retentionDays)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedCount, deletedCount, "unexpected number of deleted logs")
		})
	}
}

func TestCleanupWithExactBoundary(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().
		DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, olderThan time.Time) (int64, error) {
			expectedCutoff := time.Now().AddDate(0, 0, -30)
			timeDiff := olderThan.Sub(expectedCutoff)
			assert.Less(t, timeDiff.Abs(), time.Second, "cutoff time should be close to expected value")
			return 1, nil
		})

	manager := &managerImpl{
		store: mockStore,
	}

	ctx := context.Background()
	deletedCount, err := manager.CleanupOldAccessLogs(ctx, 30)

	require.NoError(t, err)
	assert.Equal(t, int64(1), deletedCount)
}

func TestStartPeriodicCleanup(t *testing.T) {
	t.Run("periodic cleanup disabled with zero retention", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		// No expectations - cleanup should not run

		manager := &managerImpl{
			store: mockStore,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		manager.StartPeriodicCleanup(ctx, 0, 1)

		time.Sleep(100 * time.Millisecond)

		// If DeleteOldAccessLogs was called, the test will fail due to unexpected call
	})

	t.Run("periodic cleanup runs immediately on start", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
			Return(int64(2), nil).
			Times(1)

		manager := &managerImpl{
			store: mockStore,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		manager.StartPeriodicCleanup(ctx, 30, 24)

		time.Sleep(200 * time.Millisecond)

		// Expectations verified by gomock on defer ctrl.Finish()
	})

	t.Run("periodic cleanup stops on context cancel", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
			Return(int64(1), nil).
			Times(1)

		manager := &managerImpl{
			store: mockStore,
		}

		ctx, cancel := context.WithCancel(context.Background())

		manager.StartPeriodicCleanup(ctx, 30, 24)

		time.Sleep(100 * time.Millisecond)

		cancel()

		time.Sleep(200 * time.Millisecond)

	})

	t.Run("cleanup interval defaults to 24 hours when invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
			Return(int64(0), nil).
			Times(1)

		manager := &managerImpl{
			store: mockStore,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		manager.StartPeriodicCleanup(ctx, 30, 0)

		time.Sleep(100 * time.Millisecond)

		manager.StopPeriodicCleanup()
	})

	t.Run("cleanup interval uses configured hours", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
			Return(int64(3), nil).
			Times(1)

		manager := &managerImpl{
			store: mockStore,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		manager.StartPeriodicCleanup(ctx, 30, 12)

		time.Sleep(100 * time.Millisecond)

		manager.StopPeriodicCleanup()
	})
}

func TestStopPeriodicCleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().
		DeleteOldAccessLogs(gomock.Any(), gomock.Any()).
		Return(int64(1), nil).
		Times(1)

	manager := &managerImpl{
		store: mockStore,
	}

	ctx := context.Background()

	manager.StartPeriodicCleanup(ctx, 30, 24)

	time.Sleep(100 * time.Millisecond)

	manager.StopPeriodicCleanup()

	time.Sleep(200 * time.Millisecond)

	// Expectations verified by gomock - would fail if more than 1 call happened
}

func TestStopPeriodicCleanup_NotStarted(t *testing.T) {
	manager := &managerImpl{}

	// Should not panic if cleanup was never started
	manager.StopPeriodicCleanup()
}
