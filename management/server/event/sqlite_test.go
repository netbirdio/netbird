package event

import (
	"fmt"
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
	eventTime := time.Now()
	_, err = store.Save(Event{
		Timestamp:  eventTime,
		Operation:  "cool operation",
		Type:       ManagementEvent,
		ModifierID: "user_1",
		TargetID:   "peer_1",
		AccountID:  accountID,
	})
	if err != nil {
		t.Fatal(err)
		return
	}

	result, err := store.GetSince(accountID, eventTime.Add(-10*time.Second))
	if err != nil {
		t.Fatal(err)
		return
	}

	fmt.Println(result)

	result, err = store.GetLast(accountID, 10)
	if err != nil {
		t.Fatal(err)
		return
	}

	fmt.Println(result)
}
