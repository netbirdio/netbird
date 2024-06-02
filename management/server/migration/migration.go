package migration

import (
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// MigrateFieldFromGobToJSON migrates a column from Gob encoding to JSON encoding.
// T is the type of the model that contains the field to be migrated.
// S is the type of the field to be migrated.
func MigrateFieldFromGobToJSON[T any, S any](db *gorm.DB, fieldName string) error {

	oldColumnName := fieldName
	newColumnName := fieldName + "_tmp"

	var model T

	if !db.Migrator().HasTable(&model) {
		log.Debugf("Table for %T does not exist, no migration needed", model)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(model)
	if err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	tableName := stmt.Schema.Table

	var item string
	if err := db.Model(model).Select(oldColumnName).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Debugf("No records in table %s, no migration needed", tableName)
			return nil
		}
		return fmt.Errorf("fetch first record: %w", err)
	}

	var js json.RawMessage
	var syntaxError *json.SyntaxError
	err = json.Unmarshal([]byte(item), &js)
	if err == nil || !errors.As(err, &syntaxError) {
		log.Debugf("No migration needed for %s, %s", tableName, fieldName)
		return nil
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT", tableName, newColumnName)).Error; err != nil {
			return fmt.Errorf("add column %s: %w", newColumnName, err)
		}

		var rows []map[string]any
		if err := tx.Table(tableName).Select("id", oldColumnName).Find(&rows).Error; err != nil {
			return fmt.Errorf("find rows: %w", err)
		}

		for _, row := range rows {
			var field S

			str, ok := row[oldColumnName].(string)
			if !ok {
				return fmt.Errorf("type assertion failed")
			}
			reader := strings.NewReader(str)

			if err := gob.NewDecoder(reader).Decode(&field); err != nil {
				return fmt.Errorf("gob decode error: %w", err)
			}

			jsonValue, err := json.Marshal(field)
			if err != nil {
				return fmt.Errorf("re-encode to JSON: %w", err)
			}

			if err := tx.Table(tableName).Where("id = ?", row["id"]).Update(newColumnName, jsonValue).Error; err != nil {
				return fmt.Errorf("update row: %w", err)
			}
		}

		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", tableName, oldColumnName)).Error; err != nil {
			return fmt.Errorf("drop column %s: %w", oldColumnName, err)
		}
		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s", tableName, newColumnName, oldColumnName)).Error; err != nil {
			return fmt.Errorf("rename column %s to %s: %w", newColumnName, oldColumnName, err)
		}

		return nil
	}); err != nil {
		return err
	}

	log.Infof("Migration of %s.%s from gob to json completed", tableName, fieldName)

	return nil
}

// MigrateNetIPFieldFromBlobToJSON migrates a Net IP column from Blob encoding to JSON encoding.
// T is the type of the model that contains the field to be migrated.
func MigrateNetIPFieldFromBlobToJSON[T any](db *gorm.DB, fieldName string, indexName string) error {
	oldColumnName := fieldName
	newColumnName := fieldName + "_tmp"

	var model T

	if !db.Migrator().HasTable(&model) {
		log.Printf("Table for %T does not exist, no migration needed", model)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(&model)
	if err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	tableName := stmt.Schema.Table

	var item sql.NullString
	if err := db.Model(&model).Select(oldColumnName).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("No records in table %s, no migration needed", tableName)
			return nil
		}
		return fmt.Errorf("fetch first record: %w", err)
	}

	if item.Valid {
		var js json.RawMessage
		var syntaxError *json.SyntaxError
		err = json.Unmarshal([]byte(item.String), &js)
		if err == nil || !errors.As(err, &syntaxError) {
			log.Debugf("No migration needed for %s, %s", tableName, fieldName)
			return nil
		}
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT", tableName, newColumnName)).Error; err != nil {
			return fmt.Errorf("add column %s: %w", newColumnName, err)
		}

		var rows []map[string]any
		if err := tx.Table(tableName).Select("id", oldColumnName).Find(&rows).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("No records in table %s, no migration needed", tableName)
				return nil
			}
			return fmt.Errorf("find rows: %w", err)
		}

		for _, row := range rows {
			var blobValue string
			if columnValue := row[oldColumnName]; columnValue != nil {
				value, ok := columnValue.(string)
				if !ok {
					return fmt.Errorf("type assertion failed")
				}
				blobValue = value
			}

			columnIpValue := net.IP(blobValue)
			if net.ParseIP(columnIpValue.String()) == nil {
				log.Debugf("failed to parse %s as ip, fallback to ipv6 loopback", oldColumnName)
				columnIpValue = net.IPv6loopback
			}

			jsonValue, err := json.Marshal(columnIpValue)
			if err != nil {
				return fmt.Errorf("re-encode to JSON: %w", err)
			}

			if err := tx.Table(tableName).Where("id = ?", row["id"]).Update(newColumnName, jsonValue).Error; err != nil {
				return fmt.Errorf("update row: %w", err)
			}
		}

		if indexName != "" {
			if err := tx.Migrator().DropIndex(&model, indexName); err != nil {
				return fmt.Errorf("drop index %s: %w", indexName, err)
			}
		}

		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", tableName, oldColumnName)).Error; err != nil {
			return fmt.Errorf("drop column %s: %w", oldColumnName, err)
		}
		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s", tableName, newColumnName, oldColumnName)).Error; err != nil {
			return fmt.Errorf("rename column %s to %s: %w", newColumnName, oldColumnName, err)
		}
		return nil
	}); err != nil {
		return err
	}

	log.Printf("Migration of %s.%s from blob to json completed", tableName, fieldName)

	return nil
}
