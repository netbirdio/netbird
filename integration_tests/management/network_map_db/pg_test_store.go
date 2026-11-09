//go:build integration

package networkmap_pgsql

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/uuid"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	gormstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/testutil"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func createPGTestStore(baseData string) (*networkmap_pgsql.PgStore, func()) {
	_, tmpdsn, err := testutil.CreatePostgresTestContainer()
	if err != nil {
		log.Fatalf("error starting postres container %v", err)
	}

	var db *gorm.DB
	for i := range 5 {
		db, err = gorm.Open(postgres.Open(tmpdsn), &gorm.Config{})

		if err == nil {
			break
		}

		if i < 5 {
			waitTime := time.Duration(100*(i+1)) * time.Millisecond
			time.Sleep(waitTime)
			continue
		}

		log.Fatalf("error connecting to postres db %v", err)
	}

	var cleanup func()
	dsn, cleanup, err := createRandomDB(tmpdsn, db)
	sqlDB, _ := db.DB()
	if sqlDB != nil {
		sqlDB.Close()
	}
	if err != nil {
		log.Fatalf("error creating postres db %v", err)
	}

	_, err = gormstore.NewPostgresqlStoreForTests(context.TODO(), dsn, nil, false)
	if err != nil {
		log.Fatalf("error running migrations %v", err)
	}

	ctx := context.TODO()
	pgstore, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
	if err != nil {
		log.Fatal("error creating postgres store %w", err)
	}

	for _, query := range strings.Split(baseData, ";") {
		if _, err := pgstore.Pool.Exec(ctx, query); err != nil {
			log.Fatalf("error initializing db: %s", err.Error())
		}
	}

	return pgstore, cleanup
}

func createRandomDB(dsn string, db *gorm.DB) (string, func(), error) {
	dbName := fmt.Sprintf("test_db_%s", strings.ReplaceAll(uuid.New().String(), "-", "_"))

	if err := db.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName)).Error; err != nil {
		return "", nil, fmt.Errorf("failed to create database: %v", err)
	}

	originalDSN := dsn

	cleanup := func() {
		var dropDB *gorm.DB
		var err error

		dropDB, err = gorm.Open(postgres.Open(originalDSN), &gorm.Config{
			SkipDefaultTransaction: true,
			PrepareStmt:            false,
		})
		if err != nil {
			log.Errorf("failed to connect for dropping database %s: %v", dbName, err)
			return
		}
		defer func() {
			if sqlDB, _ := dropDB.DB(); sqlDB != nil {
				sqlDB.Close()
			}
		}()

		if sqlDB, _ := dropDB.DB(); sqlDB != nil {
			sqlDB.SetMaxOpenConns(1)
			sqlDB.SetMaxIdleConns(0)
			sqlDB.SetConnMaxLifetime(time.Second)
		}

		err = dropDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", dbName)).Error

		if err != nil {
			log.Errorf("failed to drop database %s: %v", dbName, err)
		}
	}

	return replaceDBName(dsn, dbName), cleanup, nil
}

func replaceDBName(dsn, newDBName string) string {
	re := regexp.MustCompile(`(?P<pre>[:/@])(?P<dbname>[^/?]+)(?P<post>\?|$)`)
	return re.ReplaceAllString(dsn, `${pre}`+newDBName+`${post}`)
}
