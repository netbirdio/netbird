package migration_test

import (
	"context"
	"encoding/gob"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/migration"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

func setupDatabase(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		PrepareStmt: true,
	})

	require.NoError(t, err, "Failed to open database")
	return db
}

func TestMigrateFieldFromGobToJSON_EmptyDB(t *testing.T) {
	db := setupDatabase(t)
	err := migration.MigrateFieldFromGobToJSON[types.Account, net.IPNet](context.Background(), db, "network_net")
	require.NoError(t, err, "Migration should not fail for an empty database")
}

func TestMigrateFieldFromGobToJSON_WithGobData(t *testing.T) {
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

	err = db.Save(&account{
		Account: types.Account{Id: "123"},
		Peers: []peer{
			{Location: location{ConnectionIP: net.IP{10, 0, 0, 1}}},
		}},
	).Error
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

	err = db.Save(&types.Account{
		Id: "1234",
		PeersG: []nbpeer.Peer{
			{Location: nbpeer.Location{ConnectionIP: net.IP{10, 0, 0, 1}}},
		}},
	).Error
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
		Id:  "1",
		Key: "EEFDAB47-C1A5-4472-8C05-71DE9A1E8382",
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
		Id:  "1",
		Key: "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=",
	}).Error
	require.NoError(t, err, "Failed to insert setup key")

	err = migration.MigrateSetupKeyToHashedSetupKey[types.SetupKey](context.Background(), db)
	require.NoError(t, err, "Migration should not fail to migrate setup key")

	var key types.SetupKey
	err = db.Model(&types.SetupKey{}).First(&key).Error
	assert.NoError(t, err, "Failed to fetch setup key")

	assert.Equal(t, "9+FQcmNd2GCxIK+SvHmtp6PPGV4MKEicDS+xuSQmvlE=", key.Key, "Key should be hashed")
}
