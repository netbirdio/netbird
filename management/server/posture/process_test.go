package posture

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/peer"
)

func TestProcessCheck_Check(t *testing.T) {
	tests := []struct {
		name    string
		input   peer.Peer
		check   ProcessCheck
		wantErr bool
		isValid bool
	}{
		{},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid, err := tt.check.Check(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}
