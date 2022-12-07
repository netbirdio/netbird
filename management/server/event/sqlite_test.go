package event

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewSQLiteStore(t *testing.T) {
	dataDir := t.TempDir()
	store, err := NewSQLiteStore(dataDir)
	if err != nil {
		t.Fatal(err)
		return
	}

	accountID := "account_1"

	for i := 0; i < 10; i++ {
		_, err = store.Save(Event{
			Timestamp:  time.Now(),
			Operation:  "cool_operation_" + fmt.Sprint(i),
			Type:       ManagementEvent,
			ModifierID: "user_" + fmt.Sprint(i),
			TargetID:   "peer_" + fmt.Sprint(i),
			AccountID:  accountID,
		})
		if err != nil {
			t.Fatal(err)
			return
		}
	}

	result, err := store.Get(accountID, 0, 10, false)
	if err != nil {
		t.Fatal(err)
		return
	}

	assert.Len(t, result, 10)
	assert.True(t, result[0].Timestamp.Before(result[len(result)-1].Timestamp))

	result, err = store.Get(accountID, 0, 5, true)
	if err != nil {
		t.Fatal(err)
		return
	}

	assert.Len(t, result, 5)
	assert.True(t, result[0].Timestamp.After(result[len(result)-1].Timestamp))
}
