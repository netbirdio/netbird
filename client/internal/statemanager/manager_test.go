package statemanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockState implements the State interface for testing
type MockState struct {
}

func (m MockState) Name() string {
	return "mock_state"
}

func (m MockState) Cleanup() error {
	return nil
}

func TestManager_PersistState_SlowWrite(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name           string
		contextTimeout time.Duration
		expectError    bool
		errorType      error
	}{
		{
			name:           "write completes before deadline",
			contextTimeout: 1 * time.Second,
			expectError:    false,
		},
		{
			name:           "write exceeds deadline",
			contextTimeout: 0,
			expectError:    true,
			errorType:      context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateFile := filepath.Join(tmpDir, tt.name+"-state.json")

			file, err := os.Create(stateFile)
			require.NoError(t, err)
			defer file.Close()

			m := New(stateFile)

			// Register and update mock state
			mockState := &MockState{}
			m.RegisterState(mockState)
			err = m.UpdateState(mockState)
			require.NoError(t, err)

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), tt.contextTimeout)
			defer cancel()

			// Attempt to persist state
			err = m.PersistState(ctx)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, context.DeadlineExceeded, err)
				assert.Len(t, m.dirty, 1)
			} else {
				assert.NoError(t, err)
				assert.FileExists(t, stateFile)
				assert.Empty(t, m.dirty)
			}
		})
	}
}
