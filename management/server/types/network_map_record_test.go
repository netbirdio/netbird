package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNetworkMapRecordCRUD(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&NetworkMapRecord{}))

	record := &NetworkMapRecord{
		PeerID:    "peer1",
		AccountID: "account1",
		MapJSON:   []byte(`{"Peers":[],"Network":null}`),
		Serial:    1,
		UpdatedAt: time.Now(),
	}
	require.NoError(t, SaveNetworkMapRecord(db, record))

	fetched, err := GetNetworkMapRecord(db, "peer1")
	require.NoError(t, err)
	require.Equal(t, record.PeerID, fetched.PeerID)
	require.Equal(t, record.AccountID, fetched.AccountID)
	require.Equal(t, record.Serial, fetched.Serial)
	require.Equal(t, record.MapJSON, fetched.MapJSON)
}

// Simulate a normalized structure for comparison
// In a real scenario, this would be split across multiple tables
// Here, we just use a struct for benchmarking

type NormalizedPeer struct {
	ID        string
	AccountID string
	Name      string
	IP        string
}

type NormalizedNetworkMap struct {
	PeerID    string
	Peers     []NormalizedPeer
	Serial    uint64
	UpdatedAt time.Time
}

func BenchmarkNetworkMapRecord_StoreAndRetrieve_JSON(b *testing.B) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		b.Fatal(err)
	}
	db.AutoMigrate(&NetworkMapRecord{})

	record := &NetworkMapRecord{
		PeerID:    "peer1",
		AccountID: "account1",
		MapJSON:   []byte(`{"Peers":[{"ID":"p1","AccountID":"account1","Name":"peer1","IP":"10.0.0.1"}],"Network":null}`),
		Serial:    1,
		UpdatedAt: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record.Serial = uint64(i)
		record.UpdatedAt = time.Now()
		if err := SaveNetworkMapRecord(db, record); err != nil {
			b.Fatal(err)
		}
		_, err := GetNetworkMapRecord(db, "peer1")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNetworkMapRecord_StoreAndRetrieve_Normalized(b *testing.B) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		b.Fatal(err)
	}
	db.AutoMigrate(&NormalizedPeer{})

	peers := []NormalizedPeer{{ID: "p1", AccountID: "account1", Name: "peer1", IP: "10.0.0.1"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, peer := range peers {
			if err := db.Save(&peer).Error; err != nil {
				b.Fatal(err)
			}
		}
		var fetched []NormalizedPeer
		if err := db.Find(&fetched, "account_id = ?", "account1").Error; err != nil {
			b.Fatal(err)
		}
	}
}
