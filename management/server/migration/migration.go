package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	b64 "encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetColumnName(db *gorm.DB, column string) string {
	if db.Name() == "mysql" {
		return fmt.Sprintf("`%s`", column)
	}
	return column
}

// MigrateFieldFromGobToJSON migrates a column from Gob encoding to JSON encoding.
// T is the type of the model that contains the field to be migrated.
// S is the type of the field to be migrated.
func MigrateFieldFromGobToJSON[T any, S any](ctx context.Context, db *gorm.DB, fieldName string) error {
	orgColumnName := fieldName
	oldColumnName := GetColumnName(db, orgColumnName)
	newColumnName := fieldName + "_tmp"

	var model T

	if !db.Migrator().HasTable(&model) {
		log.WithContext(ctx).Debugf("Table for %T does not exist, no migration needed", model)
		return nil
	}

	if !db.Migrator().HasColumn(&model, fieldName) {
		log.WithContext(ctx).Debugf("Table for %T does not have column %s, no migration needed", model, fieldName)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(model)
	if err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	tableName := stmt.Schema.Table

	var sqliteItem sql.NullString
	if err := db.Model(model).Select(oldColumnName).First(&sqliteItem).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.WithContext(ctx).Debugf("No records in table %s, no migration needed", tableName)
			return nil
		}
		return fmt.Errorf("fetch first record: %w", err)
	}

	item := sqliteItem.String

	var js json.RawMessage
	var syntaxError *json.SyntaxError
	err = json.Unmarshal([]byte(item), &js)
	// if the item is JSON parsable or an empty string it can not be gob encoded
	if err == nil || !errors.As(err, &syntaxError) || item == "" {
		log.WithContext(ctx).Debugf("No migration needed for %s, %s", tableName, fieldName)
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

			str, ok := row[orgColumnName].(string)
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

	log.WithContext(ctx).Infof("Migration of %s.%s from gob to json completed", tableName, fieldName)

	return nil
}

// MigrateNetIPFieldFromBlobToJSON migrates a Net IP column from Blob encoding to JSON encoding.
// T is the type of the model that contains the field to be migrated.
func MigrateNetIPFieldFromBlobToJSON[T any](ctx context.Context, db *gorm.DB, fieldName string, indexName string) error {
	orgColumnName := fieldName
	oldColumnName := GetColumnName(db, orgColumnName)
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
			log.WithContext(ctx).Debugf("No migration needed for %s, %s", tableName, fieldName)
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
			if columnValue := row[orgColumnName]; columnValue != nil {
				value, ok := columnValue.(string)
				if !ok {
					return fmt.Errorf("type assertion failed")
				}
				blobValue = value
			}

			columnIpValue := net.IP(blobValue)
			if net.ParseIP(columnIpValue.String()) == nil {
				log.WithContext(ctx).Debugf("failed to parse %s as ip, fallback to ipv6 loopback", oldColumnName)
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

func MigrateSetupKeyToHashedSetupKey[T any](ctx context.Context, db *gorm.DB) error {
	orgColumnName := "key"
	oldColumnName := GetColumnName(db, orgColumnName)
	newColumnName := "key_secret"

	var model T

	if !db.Migrator().HasTable(&model) {
		log.WithContext(ctx).Debugf("Table for %T does not exist, no migration needed", model)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(&model)
	if err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	tableName := stmt.Schema.Table

	if err := db.Transaction(func(tx *gorm.DB) error {
		if !tx.Migrator().HasColumn(&model, newColumnName) {
			log.WithContext(ctx).Infof("Column %s does not exist in table %s, adding it", newColumnName, tableName)
			if err := tx.Migrator().AddColumn(&model, newColumnName); err != nil {
				return fmt.Errorf("add column %s: %w", newColumnName, err)
			}
		}

		var rows []map[string]any
		if err := tx.Table(tableName).
			Select("id", oldColumnName, newColumnName).
			Where(newColumnName + " IS NULL OR " + newColumnName + " = ''").
			Where("SUBSTR(" + oldColumnName + ", 9, 1) = '-'").
			Find(&rows).Error; err != nil {
			return fmt.Errorf("find rows with empty secret key and matching pattern: %w", err)
		}

		if len(rows) == 0 {
			log.WithContext(ctx).Infof("No plain setup keys found in table %s, no migration needed", tableName)
			return nil
		}

		for _, row := range rows {

			var plainKey string
			if columnValue := row[orgColumnName]; columnValue != nil {
				value, ok := columnValue.(string)
				if !ok {
					return fmt.Errorf("type assertion failed")
				}
				plainKey = value
			}

			secretKey := hiddenKey(plainKey, 4)

			hashedKey := sha256.Sum256([]byte(plainKey))
			encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])

			if err := tx.Table(tableName).Where("id = ?", row["id"]).Update(newColumnName, secretKey).Error; err != nil {
				return fmt.Errorf("update row with secret key: %w", err)
			}

			if err := tx.Table(tableName).Where("id = ?", row["id"]).Update(oldColumnName, encodedHashedKey).Error; err != nil {
				return fmt.Errorf("update row with hashed key: %w", err)
			}
		}

		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN IF EXISTS %s", "peers", "setup_key")).Error; err != nil {
			log.WithContext(ctx).Errorf("Failed to drop column %s: %v", "setup_key", err)
		}

		return nil
	}); err != nil {
		return err
	}

	log.Printf("Migration of plain setup key to hashed setup key completed")
	return nil
}

// hiddenKey returns the Key value hidden with "*" and a 5 character prefix.
// E.g., "831F6*******************************"
func hiddenKey(key string, length int) string {
	prefix := key[0:5]
	if length > utf8.RuneCountInString(key) {
		length = utf8.RuneCountInString(key) - len(prefix)
	}
	return prefix + strings.Repeat("*", length)
}

func MigrateNewField[T any](ctx context.Context, db *gorm.DB, columnName string, defaultValue any) error {
	var model T

	if !db.Migrator().HasTable(&model) {
		log.WithContext(ctx).Debugf("Table for %T does not exist, no migration needed", model)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(&model)
	if err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	tableName := stmt.Schema.Table

	if err := db.Transaction(func(tx *gorm.DB) error {
		if !tx.Migrator().HasColumn(&model, columnName) {
			log.WithContext(ctx).Infof("Column %s does not exist in table %s, adding it", columnName, tableName)
			if err := tx.Migrator().AddColumn(&model, columnName); err != nil {
				return fmt.Errorf("add column %s: %w", columnName, err)
			}
		}

		var rows []map[string]any
		if err := tx.Table(tableName).Select("id", columnName).Where(columnName + " IS NULL").Find(&rows).Error; err != nil {
			return fmt.Errorf("failed to find rows with empty %s: %w", columnName, err)
		}

		if len(rows) == 0 {
			log.WithContext(ctx).Infof("No rows with empty %s found in table %s, no migration needed", columnName, tableName)
			return nil
		}

		for _, row := range rows {
			if err := tx.Table(tableName).Where("id = ?", row["id"]).Update(columnName, defaultValue).Error; err != nil {
				return fmt.Errorf("failed to update row with id %v: %w", row["id"], err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	log.WithContext(ctx).Infof("Migration of empty %s to default value in table %s completed", columnName, tableName)
	return nil
}

func DropIndex[T any](ctx context.Context, db *gorm.DB, indexName string) error {
	var model T

	if !db.Migrator().HasTable(&model) {
		log.WithContext(ctx).Debugf("table for %T does not exist, no migration needed", model)
		return nil
	}

	if !db.Migrator().HasIndex(&model, indexName) {
		log.WithContext(ctx).Debugf("index %s does not exist in table %T, no migration needed", indexName, model)
		return nil
	}

	if err := db.Migrator().DropIndex(&model, indexName); err != nil {
		return fmt.Errorf("failed to drop index %s: %w", indexName, err)
	}

	log.WithContext(ctx).Infof("dropped index %s from table %T", indexName, model)
	return nil
}

func CreateIndexIfNotExists[T any](ctx context.Context, db *gorm.DB, indexName string, columns ...string) error {
	var model T

	if !db.Migrator().HasTable(&model) {
		log.WithContext(ctx).Debugf("table for %T does not exist, no migration needed", model)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(&model); err != nil {
		return fmt.Errorf("failed to parse model schema: %w", err)
	}
	tableName := stmt.Schema.Table
	dialect := db.Name()

	if db.Migrator().HasIndex(&model, indexName) {
		log.WithContext(ctx).Infof("index %s already exists on table %s", indexName, tableName)
		return nil
	}

	var columnClause string
	if dialect == "mysql" {
		var withLength []string
		for _, col := range columns {
			quotedCol := fmt.Sprintf("`%s`", col)
			if col == "ip" || col == "dns_label" || col == "key" {
				withLength = append(withLength, fmt.Sprintf("%s(64)", quotedCol))
			} else {
				withLength = append(withLength, quotedCol)
			}
		}
		columnClause = strings.Join(withLength, ", ")
	} else {
		columnClause = strings.Join(columns, ", ")
	}

	createStmt := fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (%s)", indexName, tableName, columnClause)
	if dialect == "postgres" || dialect == "sqlite" {
		createStmt = strings.Replace(createStmt, "CREATE UNIQUE INDEX", "CREATE UNIQUE INDEX IF NOT EXISTS", 1)
	}

	log.WithContext(ctx).Infof("executing index creation: %s", createStmt)
	if err := db.Exec(createStmt).Error; err != nil {
		return fmt.Errorf("failed to create index %s: %w", indexName, err)
	}

	log.WithContext(ctx).Infof("successfully created index %s on table %s", indexName, tableName)
	return nil
}

func MigrateJsonToTable[T any](ctx context.Context, db *gorm.DB, columnName string, mapperFunc func(accountID string, id string, value string) any) error {
	var model T

	if !db.Migrator().HasTable(&model) {
		log.WithContext(ctx).Debugf("table for %T does not exist, no migration needed", model)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(&model)
	if err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	tableName := stmt.Schema.Table

	if !db.Migrator().HasColumn(&model, columnName) {
		log.WithContext(ctx).Debugf("column %s does not exist in table %s, no migration needed", columnName, tableName)
		return nil
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		var rows []map[string]any
		if err := tx.Table(tableName).Select("id", "account_id", columnName).Find(&rows).Error; err != nil {
			return fmt.Errorf("find rows: %w", err)
		}

		for _, row := range rows {
			jsonValue, ok := row[columnName].(string)
			if !ok || jsonValue == "" {
				continue
			}

			var data []string
			if err := json.Unmarshal([]byte(jsonValue), &data); err != nil {
				return fmt.Errorf("unmarshal json: %w", err)
			}

			for _, value := range data {
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(
					mapperFunc(row["account_id"].(string), row["id"].(string), value),
				).Error; err != nil {
					return fmt.Errorf("failed to insert id %v: %w", row["id"], err)
				}
			}
		}

		if err := tx.Migrator().DropColumn(&model, columnName); err != nil {
			return fmt.Errorf("drop column %s: %w", columnName, err)
		}

		return nil
	}); err != nil {
		return err
	}

	log.WithContext(ctx).Infof("Migration of JSON field %s from table %s into separate table completed", columnName, tableName)
	return nil
}

func RemoveDuplicatePeerKeys(ctx context.Context, db *gorm.DB) error {
	if !db.Migrator().HasTable("peers") {
		log.WithContext(ctx).Debug("peers table does not exist, skipping duplicate key cleanup")
		return nil
	}

	keyColumn := GetColumnName(db, "key")

	var duplicates []struct {
		Key   string
		Count int64
	}

	if err := db.Table("peers").
		Select(keyColumn + ", COUNT(*) as count").
		Group(keyColumn).
		Having("COUNT(*) > 1").
		Find(&duplicates).Error; err != nil {
		return fmt.Errorf("find duplicate keys: %w", err)
	}

	if len(duplicates) == 0 {
		return nil
	}

	log.WithContext(ctx).Warnf("Found %d duplicate peer keys, cleaning up", len(duplicates))

	for _, dup := range duplicates {
		var peerIDs []string
		if err := db.Table("peers").
			Select("id").
			Where(keyColumn+" = ?", dup.Key).
			Order("peer_status_last_seen DESC").
			Pluck("id", &peerIDs).Error; err != nil {
			return fmt.Errorf("get peers for key: %w", err)
		}

		if len(peerIDs) <= 1 {
			continue
		}

		idsToDelete := peerIDs[1:]

		if err := db.Table("peers").Where("id IN ?", idsToDelete).Delete(nil).Error; err != nil {
			return fmt.Errorf("delete duplicate peers: %w", err)
		}
	}

	return nil
}
