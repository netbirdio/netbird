//go:build integration

package networkmap_pgsql

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	gormstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func createSqliteTestStore(baseData string) (*networkmap_sqlite.SqliteStore, func()) {
	storeSqliteFileName := ":memory:"
	storeStr := fmt.Sprintf("%s?cache=shared", storeSqliteFileName)
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = storeSqliteFileName
	}

	db, err := gorm.Open(sqlite.Open(storeStr), &gorm.Config{})
	if err != nil {
		log.Fatalf("error initializing db: %s", err.Error())
	}
	_, err = gormstore.NewSqlStore(context.TODO(), db, types.SqliteStoreEngine, nil, false)
	if err != nil {
		log.Fatalf("error initializing db: %s", err.Error())
	}

	sqldb, err := db.DB()
	if err != nil {
		log.Fatalf("error initializing db: %s", err.Error())

	}
	for _, query := range strings.Split(baseData, ";") {
		if _, err := sqldb.Exec(query); err != nil {
			log.Fatalf("error initializing db: %s", err.Error())
		}
	}

	return &networkmap_sqlite.SqliteStore{Db: sqldb}, func() {}
}
