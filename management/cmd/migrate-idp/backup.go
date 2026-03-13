package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/types"
)

const (
	storeDBFile  = "store.db"
	eventsDBFile = "events.db"
)

// backupDatabases creates backups of SQLite database files before migration.
// For PostgreSQL/MySQL, it prints instructions for the operator to run pg_dump/mysqldump.
func backupDatabases(dataDir string, engine types.Engine) error {
	switch engine {
	case types.SqliteStoreEngine:
		for _, dbFile := range []string{storeDBFile, eventsDBFile} {
			src := filepath.Join(dataDir, dbFile)
			if _, err := os.Stat(src); os.IsNotExist(err) {
				log.Infof("skipping backup of %s (file does not exist)", src)
				continue
			}
			if err := backupSQLiteFile(src); err != nil {
				return fmt.Errorf("backup %s: %w", dbFile, err)
			}
		}
	case types.PostgresStoreEngine:
		log.Warn("PostgreSQL detected — automatic backup is not supported. " +
			"Please ensure you have a recent pg_dump backup before proceeding.")
	case types.MysqlStoreEngine:
		log.Warn("MySQL detected — automatic backup is not supported. " +
			"Please ensure you have a recent mysqldump backup before proceeding.")
	}
	return nil
}

// backupSQLiteFile copies a SQLite database file to a timestamped backup.
func backupSQLiteFile(srcPath string) error {
	timestamp := time.Now().Format("20060102-150405")
	dstPath := fmt.Sprintf("%s.backup-%s", srcPath, timestamp)

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	log.Infof("backed up %s -> %s", srcPath, dstPath)
	return nil
}
