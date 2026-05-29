package owner

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOwnerUIDsFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		unset    bool
		want     []UID
	}{
		{
			name:  "unset returns nil",
			unset: true,
			want:  nil,
		},
		{
			name:     "empty string returns nil",
			envValue: "",
			want:     nil,
		},
		{
			name:     "single UID",
			envValue: "1000",
			want:     []UID{1000},
		},
		{
			name:     "multiple UIDs",
			envValue: "1000,1001,1002",
			want:     []UID{1000, 1001, 1002},
		},
		{
			name:     "spaces around UIDs",
			envValue: " 1000 , 1001 ",
			want:     []UID{1000, 1001},
		},
		{
			name:     "invalid UID skipped",
			envValue: "1000,notanumber,1001",
			want:     []UID{1000, 1001},
		},
		{
			name:     "all invalid returns empty slice",
			envValue: "abc,def",
			want:     []UID{},
		},
		{
			name:     "trailing comma",
			envValue: "1000,",
			want:     []UID{1000},
		},
		{
			name:     "zero UID is valid",
			envValue: "0",
			want:     []UID{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvOwnerUID, tt.envValue)
			if tt.unset {
				os.Unsetenv(EnvOwnerUID)
			}

			got := OwnerUIDsFromEnv()

			if tt.want == nil {
				require.Nil(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
