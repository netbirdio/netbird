package activity

import (
	"testing"
	"time"
)

func TestNewSQLiteStore(t *testing.T) {
	//dataDir := t.TempDir()
	store, err := NewSQLiteStore("/home/braginini/wiretrustee/test/")
	if err != nil {
		t.Fatal(err)
		return
	}

	//accountID := "account_1"

	for i := 0; i < 10000; i++ {
		_, err = store.Save(&Event{
			Timestamp:   time.Now().Add(-1 * time.Minute),
			Activity:    PeerAddedByUser,
			InitiatorID: "google-oauth2|110866222733584764488",
			TargetID:    "100.101.249.29",
			AccountID:   "cebi9h3lo1hkhn1qc7cg",
		})
		if err != nil {
			t.Fatal(err)
			return
		}
	}

	/*result, err := store.Get(accountID, 0, 10, false)
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
	assert.True(t, result[0].Timestamp.After(result[len(result)-1].Timestamp))*/
}
