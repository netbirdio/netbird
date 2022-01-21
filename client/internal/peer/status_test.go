package peer

import (
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestConnStatus_String(t *testing.T) {

	tables := []struct {
		name   string
		status ConnStatus
		want   string
	}{
		{"StatusConnected", StatusConnected, "StatusConnected"},
		{"StatusDisconnected", StatusDisconnected, "StatusDisconnected"},
		{"StatusConnecting", StatusConnecting, "StatusConnecting"},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			got := table.status.String()
			assert.Equal(t, got, table.want, "they should be equal")
		})
	}

}
