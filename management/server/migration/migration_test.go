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

	err := db.AutoMigrate(&types.SetupKey{})
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
