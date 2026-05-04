package migration_test

import (
	"context"
	"encoding/gob"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/migration"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

func setupDatabase(t *testing.T) *gorm.DB {
	t.Helper()

	var db *gorm.DB
	var err error
	var dsn string
	var cleanup func()
	switch os.Getenv("NETBIRD_STORE_ENGINE") {
	case "mysql":
		cleanup, dsn, err = testutil.CreateMysqlTestContainer()
		if err != nil {
			t.Fatalf("Failed to create MySQL test container: %v", err)
		}

		if dsn == "" {
			t.Fatal("MySQL connection string is empty, ensure the test container is running")
		}

		db, err = gorm.Open(mysql.Open(dsn+"?charset=utf8&parseTime=True&loc=Local"), &gorm.Config{})
	case "postgres":
		cleanup, dsn, err = testutil.CreatePostgresTestContainer()
		if err != nil {
			t.Fatalf("Failed to create PostgreSQL test container: %v", err)
		}

		if dsn == "" {
			t.Fatalf("PostgreSQL connection string is empty, ensure the test container is running")
		}

		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	case "sqlite":
		db, err = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	default:
		db, err = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	}
	if cleanup != nil {
		t.Cleanup(cleanup)
	}

	require.NoError(t, err, "Failed to open database")
	return db
}

func TestMigrateFieldFromGobToJSON_EmptyDB(t *testing.T) {
	db := setupDatabase(t)
	err := migration.MigrateFieldFromGobToJSON[types.Account, net.IPNet](context.Background(), db, "network_net")
	require.NoError(t, err, "Migration should not fail for an empty database")
}

func TestMigrateFieldFromGobToJSON_WithGobData(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.Account{}, &route.Route{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	_, ipnet, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err, "Failed to parse CIDR")

	type network struct {
		types.Network
		Net net.IPNet `gorm:"serializer:gob"`
	}

	type account struct {
		types.Account
		Network *network `gorm:"embedded;embeddedPrefix:network_"`
	}

	err = db.Save(&account{Account: types.Account{Id: "123"}, Network: &network{Net: *ipnet}}).Error
	require.NoError(t, err, "Failed to insert Gob data")

	var gobStr string
	err = db.Model(&types.Account{}).Select("network_net").First(&gobStr).Error
	assert.NoError(t, err, "Failed to fetch Gob data")

	err = gob.NewDecoder(strings.NewReader(gobStr)).Decode(&ipnet)
	require.NoError(t, err, "Failed to decode Gob data")

	err = migration.MigrateFieldFromGobToJSON[types.Account, net.IPNet](context.Background(), db, "network_net")
	require.NoError(t, err, "Migration should not fail with Gob data")

	var jsonStr string
	db.Model(&types.Account{}).Select("network_net").First(&jsonStr)
	assert.JSONEq(t, `{"IP":"10.0.0.0","Mask":"////AA=="}`, jsonStr, "Data should be migrated")
}

func TestMigrateFieldFromGobToJSON_WithJSONData(t *testing.T) {
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.Account{}, &route.Route{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	_, ipnet, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err, "Failed to parse CIDR")

	err = db.Save(&types.Account{Network: &types.Network{Net: *ipnet}}).Error
	require.NoError(t, err, "Failed to insert JSON data")

	err = migration.MigrateFieldFromGobToJSON[types.Account, net.IPNet](context.Background(), db, "network_net")
	require.NoError(t, err, "Migration should not fail with JSON data")

	var jsonStr string
	db.Model(&types.Account{}).Select("network_net").First(&jsonStr)
	assert.JSONEq(t, `{"IP":"10.0.0.0","Mask":"////AA=="}`, jsonStr, "Data should be unchanged")
}

func TestMigrateNetIPFieldFromBlobToJSON_EmptyDB(t *testing.T) {
	db := setupDatabase(t)
	err := migration.MigrateNetIPFieldFromBlobToJSON[nbpeer.Peer](context.Background(), db, "ip", "idx_peers_account_id_ip")
	require.NoError(t, err, "Migration should not fail for an empty database")
}

func TestMigrateNetIPFieldFromBlobToJSON_WithBlobData(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.Account{}, &nbpeer.Peer{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	type location struct {
		nbpeer.Location
		ConnectionIP net.IP
	}

	type peer struct {
		nbpeer.Peer
		Location location `gorm:"embedded;embeddedPrefix:location_"`
	}

	type account struct {
		types.Account
		Peers []peer `gorm:"foreignKey:AccountID;references:id"`
	}

	a := &account{
		Account: types.Account{Id: "123"},
	}

	err = db.Save(a).Error
	require.NoError(t, err, "Failed to insert account")

	a.Peers = []peer{
		{Location: location{ConnectionIP: net.IP{10, 0, 0, 1}}},
	}

	err = db.Save(a).Error
	require.NoError(t, err, "Failed to insert blob data")

	var blobValue string
	err = db.Model(&nbpeer.Peer{}).Select("location_connection_ip").First(&blobValue).Error
	assert.NoError(t, err, "Failed to fetch blob data")

	err = migration.MigrateNetIPFieldFromBlobToJSON[nbpeer.Peer](context.Background(), db, "location_connection_ip", "")
	require.NoError(t, err, "Migration should not fail with net.IP blob data")

	var jsonStr string
	db.Model(&nbpeer.Peer{}).Select("location_connection_ip").First(&jsonStr)
	assert.JSONEq(t, `"10.0.0.1"`, jsonStr, "Data should be migrated")
}

func TestMigrateNetIPFieldFromBlobToJSON_WithJSONData(t *testing.T) {
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.Account{}, &nbpeer.Peer{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	account := &types.Account{
		Id: "1234",
	}

	err = db.Save(account).Error
	require.NoError(t, err, "Failed to insert account")

	account.PeersG = []nbpeer.Peer{
		{AccountID: "1234", Location: nbpeer.Location{ConnectionIP: net.IP{10, 0, 0, 1}}},
	}

	err = db.Save(account).Error
	require.NoError(t, err, "Failed to insert JSON data")

	err = migration.MigrateNetIPFieldFromBlobToJSON[nbpeer.Peer](context.Background(), db, "location_connection_ip", "")
	require.NoError(t, err, "Migration should not fail with net.IP JSON data")

	var jsonStr string
	db.Model(&nbpeer.Peer{}).Select("location_connection_ip").First(&jsonStr)
	assert.JSONEq(t, `"10.0.0.1"`, jsonStr, "Data should be unchanged")
}

func TestMigrateSetupKeyToHashedSetupKey_ForPlainKey(t *testing.T) {
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.SetupKey{}, &nbpeer.Peer{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	err = db.Save(&types.SetupKey{
		Id:        "1",
		Key:       "EEFDAB47-C1A5-4472-8C05-71DE9A1E8382",
		UpdatedAt: time.Now(),
	}).Error
	require.NoError(t, err, "Failed to insert setup key")

	err = migration.MigrateSetupKeyToHashedSetupKey[types.SetupKey](context.Background(), db)
	require.NoError(t, err, "Migration should not fail to migrate setup key")

	var key types.SetupKey
	err = db.Model(&types.SetupKey{}).First(&key).Error
	assert.NoError(t, err, "Failed to fetch setup key")

	assert.Equal(t, "EEFDA****", key.KeySecret, "Key should be secret")
	assert.Equal(t, "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=", key.Key, "Key should be hashed")
}

func TestMigrateSetupKeyToHashedSetupKey_ForAlreadyMigratedKey_Case1(t *testing.T) {
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.SetupKey{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	err = db.Save(&types.SetupKey{
		Id:        "1",
		Key:       "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=",
		KeySecret: "EEFDA****",
		UpdatedAt: time.Now(),
	}).Error
	require.NoError(t, err, "Failed to insert setup key")

	err = migration.MigrateSetupKeyToHashedSetupKey[types.SetupKey](context.Background(), db)
	require.NoError(t, err, "Migration should not fail to migrate setup key")

	var key types.SetupKey
	err = db.Model(&types.SetupKey{}).First(&key).Error
	assert.NoError(t, err, "Failed to fetch setup key")

	assert.Equal(t, "EEFDA****", key.KeySecret, "Key should be secret")
	assert.Equal(t, "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=", key.Key, "Key should be hashed")
}

func TestMigrateSetupKeyToHashedSetupKey_ForAlreadyMigratedKey_Case2(t *testing.T) {
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.SetupKey{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	err = db.Save(&types.SetupKey{
		Id:        "1",
		Key:       "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=",
		UpdatedAt: time.Now(),
	}).Error
	require.NoError(t, err, "Failed to insert setup key")

	err = migration.MigrateSetupKeyToHashedSetupKey[types.SetupKey](context.Background(), db)
	require.NoError(t, err, "Migration should not fail to migrate setup key")

	var key types.SetupKey
	err = db.Model(&types.SetupKey{}).First(&key).Error
	assert.NoError(t, err, "Failed to fetch setup key")

	assert.Equal(t, "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=", key.Key, "Key should be hashed")
}

func TestDropIndex(t *testing.T) {
	db := setupDatabase(t)

	err := db.AutoMigrate(&types.SetupKey{})
	require.NoError(t, err, "Failed to auto-migrate tables")

	err = db.Save(&types.SetupKey{
		Id:        "1",
		Key:       "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=",
		UpdatedAt: time.Now(),
	}).Error
	require.NoError(t, err, "Failed to insert setup key")

	exist := db.Migrator().HasIndex(&types.SetupKey{}, "idx_setup_keys_account_id")
	assert.True(t, exist, "Should have the index")

	err = migration.DropIndex[types.SetupKey](context.Background(), db, "idx_setup_keys_account_id")
	require.NoError(t, err, "Migration should not fail to remove index")

	exist = db.Migrator().HasIndex(&types.SetupKey{}, "idx_setup_keys_account_id")
	assert.False(t, exist, "Should not have the index")
}

func TestCreateIndex(t *testing.T) {
	db := setupDatabase(t)
	err := db.AutoMigrate(&nbpeer.Peer{})
	assert.NoError(t, err, "Failed to auto-migrate tables")

	indexName := "idx_account_ip"

	err = migration.CreateIndexIfNotExists[nbpeer.Peer](context.Background(), db, indexName, "account_id", "ip")
	assert.NoError(t, err, "Migration should not fail to create index")

	exist := db.Migrator().HasIndex(&nbpeer.Peer{}, indexName)
	assert.True(t, exist, "Should have the index")
}

func TestCreateIndexIfExists(t *testing.T) {
	db := setupDatabase(t)
	err := db.AutoMigrate(&nbpeer.Peer{})
	assert.NoError(t, err, "Failed to auto-migrate tables")

	indexName := "idx_account_ip"

	err = migration.CreateIndexIfNotExists[nbpeer.Peer](context.Background(), db, indexName, "account_id", "ip")
	assert.NoError(t, err, "Migration should not fail to create index")

	exist := db.Migrator().HasIndex(&nbpeer.Peer{}, indexName)
	assert.True(t, exist, "Should have the index")

	err = migration.CreateIndexIfNotExists[nbpeer.Peer](context.Background(), db, indexName, "account_id", "ip")
	assert.NoError(t, err, "Create index should not fail if index exists")

	exist = db.Migrator().HasIndex(&nbpeer.Peer{}, indexName)
	assert.True(t, exist, "Should have the index")
}

type testPeer struct {
	ID                  string `gorm:"primaryKey"`
	Key                 string `gorm:"index"`
	PeerStatusLastSeen  time.Time
	PeerStatusConnected bool
}

func (testPeer) TableName() string {
	return "peers"
}

func setupPeerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&testPeer{})
	err := db.AutoMigrate(&testPeer{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func TestRemoveDuplicatePeerKeys_NoDuplicates(t *testing.T) {
	db := setupPeerTestDB(t)

	now := time.Now()
	peers := []testPeer{
		{ID: "peer1", Key: "key1", PeerStatusLastSeen: now},
		{ID: "peer2", Key: "key2", PeerStatusLastSeen: now},
		{ID: "peer3", Key: "key3", PeerStatusLastSeen: now},
	}

	for _, p := range peers {
		err := db.Create(&p).Error
		require.NoError(t, err)
	}

	err := migration.RemoveDuplicatePeerKeys(context.Background(), db)
	require.NoError(t, err)

	var count int64
	db.Model(&testPeer{}).Count(&count)
	assert.Equal(t, int64(len(peers)), count, "All peers should remain when no duplicates")
}

func TestRemoveDuplicatePeerKeys_WithDuplicates(t *testing.T) {
	db := setupPeerTestDB(t)

	now := time.Now()
	peers := []testPeer{
		{ID: "peer1", Key: "key1", PeerStatusLastSeen: now.Add(-2 * time.Hour)},
		{ID: "peer2", Key: "key1", PeerStatusLastSeen: now.Add(-1 * time.Hour)},
		{ID: "peer3", Key: "key1", PeerStatusLastSeen: now},
		{ID: "peer4", Key: "key2", PeerStatusLastSeen: now},
		{ID: "peer5", Key: "key3", PeerStatusLastSeen: now.Add(-1 * time.Hour)},
		{ID: "peer6", Key: "key3", PeerStatusLastSeen: now},
	}

	for _, p := range peers {
		err := db.Create(&p).Error
		require.NoError(t, err)
	}

	err := migration.RemoveDuplicatePeerKeys(context.Background(), db)
	require.NoError(t, err)

	var count int64
	db.Model(&testPeer{}).Count(&count)
	assert.Equal(t, int64(3), count, "Should have 3 peers after removing duplicates")

	var remainingPeers []testPeer
	err = db.Find(&remainingPeers).Error
	require.NoError(t, err)

	remainingIDs := make(map[string]bool)
	for _, p := range remainingPeers {
		remainingIDs[p.ID] = true
	}

	assert.True(t, remainingIDs["peer3"], "peer3 should remain (most recent for key1)")
	assert.True(t, remainingIDs["peer4"], "peer4 should remain (only peer for key2)")
	assert.True(t, remainingIDs["peer6"], "peer6 should remain (most recent for key3)")

	assert.False(t, remainingIDs["peer1"], "peer1 should be deleted (older duplicate)")
	assert.False(t, remainingIDs["peer2"], "peer2 should be deleted (older duplicate)")
	assert.False(t, remainingIDs["peer5"], "peer5 should be deleted (older duplicate)")
}

func TestRemoveDuplicatePeerKeys_EmptyTable(t *testing.T) {
	db := setupPeerTestDB(t)

	err := migration.RemoveDuplicatePeerKeys(context.Background(), db)
	require.NoError(t, err, "Should not fail on empty table")
}

func TestRemoveDuplicatePeerKeys_NoTable(t *testing.T) {
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&testPeer{})

	err := migration.RemoveDuplicatePeerKeys(context.Background(), db)
	require.NoError(t, err, "Should not fail when table does not exist")
}

type testParent struct {
	ID string `gorm:"primaryKey"`
}

func (testParent) TableName() string {
	return "test_parents"
}

type testChild struct {
	ID       string `gorm:"primaryKey"`
	ParentID string
}

func (testChild) TableName() string {
	return "test_children"
}

type testChildWithFK struct {
	ID       string      `gorm:"primaryKey"`
	ParentID string      `gorm:"index"`
	Parent   *testParent `gorm:"foreignKey:ParentID"`
}

func (testChildWithFK) TableName() string {
	return "test_children"
}

func setupOrphanTestDB(t *testing.T, models ...any) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	for _, m := range models {
		_ = db.Migrator().DropTable(m)
	}
	err := db.AutoMigrate(models...)
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func TestCleanupOrphanedResources_NoChildTable(t *testing.T) {
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&testChild{})
	_ = db.Migrator().DropTable(&testParent{})

	err := migration.CleanupOrphanedResources[testChild, testParent](context.Background(), db, "parent_id")
	require.NoError(t, err, "Should not fail when child table does not exist")
}

func TestCleanupOrphanedResources_NoParentTable(t *testing.T) {
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&testParent{})
	_ = db.Migrator().DropTable(&testChild{})

	err := db.AutoMigrate(&testChild{})
	require.NoError(t, err)

	err = migration.CleanupOrphanedResources[testChild, testParent](context.Background(), db, "parent_id")
	require.NoError(t, err, "Should not fail when parent table does not exist")
}

func TestCleanupOrphanedResources_EmptyTables(t *testing.T) {
	db := setupOrphanTestDB(t, &testParent{}, &testChild{})

	err := migration.CleanupOrphanedResources[testChild, testParent](context.Background(), db, "parent_id")
	require.NoError(t, err, "Should not fail on empty tables")

	var count int64
	db.Model(&testChild{}).Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestCleanupOrphanedResources_NoOrphans(t *testing.T) {
	db := setupOrphanTestDB(t, &testParent{}, &testChild{})

	require.NoError(t, db.Create(&testParent{ID: "p1"}).Error)
	require.NoError(t, db.Create(&testParent{ID: "p2"}).Error)
	require.NoError(t, db.Create(&testChild{ID: "c1", ParentID: "p1"}).Error)
	require.NoError(t, db.Create(&testChild{ID: "c2", ParentID: "p2"}).Error)

	err := migration.CleanupOrphanedResources[testChild, testParent](context.Background(), db, "parent_id")
	require.NoError(t, err)

	var count int64
	db.Model(&testChild{}).Count(&count)
	assert.Equal(t, int64(2), count, "All children should remain when no orphans")
}

func TestCleanupOrphanedResources_AllOrphans(t *testing.T) {
	db := setupOrphanTestDB(t, &testParent{}, &testChild{})

	require.NoError(t, db.Exec("INSERT INTO test_children (id, parent_id) VALUES (?, ?)", "c1", "gone1").Error)
	require.NoError(t, db.Exec("INSERT INTO test_children (id, parent_id) VALUES (?, ?)", "c2", "gone2").Error)
	require.NoError(t, db.Exec("INSERT INTO test_children (id, parent_id) VALUES (?, ?)", "c3", "gone3").Error)

	err := migration.CleanupOrphanedResources[testChild, testParent](context.Background(), db, "parent_id")
	require.NoError(t, err)

	var count int64
	db.Model(&testChild{}).Count(&count)
	assert.Equal(t, int64(0), count, "All orphaned children should be deleted")
}

func TestCleanupOrphanedResources_MixedValidAndOrphaned(t *testing.T) {
	db := setupOrphanTestDB(t, &testParent{}, &testChild{})

	require.NoError(t, db.Create(&testParent{ID: "p1"}).Error)
	require.NoError(t, db.Create(&testParent{ID: "p2"}).Error)

	require.NoError(t, db.Create(&testChild{ID: "c1", ParentID: "p1"}).Error)
	require.NoError(t, db.Create(&testChild{ID: "c2", ParentID: "p2"}).Error)
	require.NoError(t, db.Create(&testChild{ID: "c3", ParentID: "p1"}).Error)

	require.NoError(t, db.Exec("INSERT INTO test_children (id, parent_id) VALUES (?, ?)", "c4", "gone1").Error)
	require.NoError(t, db.Exec("INSERT INTO test_children (id, parent_id) VALUES (?, ?)", "c5", "gone2").Error)

	err := migration.CleanupOrphanedResources[testChild, testParent](context.Background(), db, "parent_id")
	require.NoError(t, err)

	var remaining []testChild
	require.NoError(t, db.Order("id").Find(&remaining).Error)

	assert.Len(t, remaining, 3, "Only valid children should remain")
	assert.Equal(t, "c1", remaining[0].ID)
	assert.Equal(t, "c2", remaining[1].ID)
	assert.Equal(t, "c3", remaining[2].ID)
}

func TestCleanupOrphanedResources_Idempotent(t *testing.T) {
	db := setupOrphanTestDB(t, &testParent{}, &testChild{})

	require.NoError(t, db.Create(&testParent{ID: "p1"}).Error)
	require.NoError(t, db.Create(&testChild{ID: "c1", ParentID: "p1"}).Error)
	require.NoError(t, db.Exec("INSERT INTO test_children (id, parent_id) VALUES (?, ?)", "c2", "gone").Error)

	ctx := context.Background()

	err := migration.CleanupOrphanedResources[testChild, testParent](ctx, db, "parent_id")
	require.NoError(t, err)

	var count int64
	db.Model(&testChild{}).Count(&count)
	assert.Equal(t, int64(1), count)

	err = migration.CleanupOrphanedResources[testChild, testParent](ctx, db, "parent_id")
	require.NoError(t, err)

	db.Model(&testChild{}).Count(&count)
	assert.Equal(t, int64(1), count, "Count should remain the same after second run")
}

func TestCleanupOrphanedResources_SkipsWhenForeignKeyExists(t *testing.T) {
	engine := os.Getenv("NETBIRD_STORE_ENGINE")
	if engine != "postgres" && engine != "mysql" {
		t.Skip("FK constraint early-exit test requires postgres or mysql")
	}

	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&testChildWithFK{})
	_ = db.Migrator().DropTable(&testParent{})

	err := db.AutoMigrate(&testParent{}, &testChildWithFK{})
	require.NoError(t, err)

	require.NoError(t, db.Create(&testParent{ID: "p1"}).Error)
	require.NoError(t, db.Create(&testParent{ID: "p2"}).Error)
	require.NoError(t, db.Create(&testChildWithFK{ID: "c1", ParentID: "p1"}).Error)
	require.NoError(t, db.Create(&testChildWithFK{ID: "c2", ParentID: "p2"}).Error)

	switch engine {
	case "postgres":
		require.NoError(t, db.Exec("ALTER TABLE test_children DROP CONSTRAINT fk_test_children_parent").Error)
		require.NoError(t, db.Exec("DELETE FROM test_parents WHERE id = ?", "p2").Error)
		require.NoError(t, db.Exec(
			"ALTER TABLE test_children ADD CONSTRAINT fk_test_children_parent "+
				"FOREIGN KEY (parent_id) REFERENCES test_parents(id) NOT VALID",
		).Error)
	case "mysql":
		require.NoError(t, db.Exec("SET FOREIGN_KEY_CHECKS = 0").Error)
		require.NoError(t, db.Exec("ALTER TABLE test_children DROP FOREIGN KEY fk_test_children_parent").Error)
		require.NoError(t, db.Exec("DELETE FROM test_parents WHERE id = ?", "p2").Error)
		require.NoError(t, db.Exec(
			"ALTER TABLE test_children ADD CONSTRAINT fk_test_children_parent "+
				"FOREIGN KEY (parent_id) REFERENCES test_parents(id)",
		).Error)
		require.NoError(t, db.Exec("SET FOREIGN_KEY_CHECKS = 1").Error)
	}

	err = migration.CleanupOrphanedResources[testChildWithFK, testParent](context.Background(), db, "parent_id")
	require.NoError(t, err)

	var count int64
	db.Model(&testChildWithFK{}).Count(&count)
	assert.Equal(t, int64(2), count, "Both rows should survive — migration must skip when FK constraint exists")
}
