package peer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnStatus_String(t *testing.T) {

	tables := []struct {
		name   string
		status ConnStatus
		want   string
	}{
		{"StatusConnected", StatusConnected, "Connected"},
		{"StatusIdle", StatusIdle, "Idle"},
		{"StatusConnecting", StatusConnecting, "Connecting"},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			got := table.status.String()
			assert.Equal(t, got, table.want, "they should be equal")
		})
	}
}
