package migration

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/types"
)

// BackfillAccountSeqIDs assigns a deterministic per-account sequential id to all
// rows of `model` whose account_seq_id is zero, then seeds account_seq_counters
// with the next free id per account. Idempotent: safe to re-run; both steps
// no-op once everything is consistent.
//
// Implemented as two table-wide SQL statements with window functions, one
// transaction. Backfilling 246k rows across 154k accounts on Postgres takes
// well under a second instead of the per-account-loop ~2 minutes.
//
// orderColumn is the column to use when assigning the deterministic ordering
// (typically the primary-key string id).
func BackfillAccountSeqIDs[T any](
	ctx context.Context,
	db *gorm.DB,
	entity types.AccountSeqEntity,
	orderColumn string,
) error {
	var model T
	if !db.Migrator().HasTable(&model) {
		log.WithContext(ctx).Debugf("backfill seq id: table for %T missing, skip", model)
		return nil
	}

	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(&model); err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	table := quoteIdent(db, stmt.Schema.Table)
	orderCol := quoteIdent(db, orderColumn)

	return db.Transaction(func(tx *gorm.DB) error {
		var pending int64
		if err := tx.Raw(
			fmt.Sprintf("SELECT count(*) FROM %s WHERE account_seq_id IS NULL OR account_seq_id = 0", table),
		).Scan(&pending).Error; err != nil {
			return fmt.Errorf("count pending on %s: %w", table, err)
		}

		if pending > 0 {
			log.WithContext(ctx).Infof("backfill seq id: %s — %d rows pending", table, pending)
			if err := backfillRankSQL(tx, table, orderCol); err != nil {
				return fmt.Errorf("rank %s: %w", table, err)
			}
		}

		if err := seedCountersSQL(tx, table, entity); err != nil {
			return fmt.Errorf("seed counters for %s: %w", entity, err)
		}
		return nil
	})
}

func quoteIdent(db *gorm.DB, name string) string {
	switch db.Dialector.Name() {
	case "mysql":
		return "`" + name + "`"
	case "postgres":
		return `"` + name + `"`
	default:
		return name
	}
}

func backfillRankSQL(db *gorm.DB, table, orderCol string) error {
	dialect := db.Dialector.Name()
	var sql string
	switch dialect {
	case "postgres", "sqlite":
		sql = fmt.Sprintf(`
WITH max_seq AS (
    SELECT account_id, COALESCE(MAX(account_seq_id), 0) AS max_seq
    FROM %s
    GROUP BY account_id
),
ranked AS (
    SELECT p.id,
           m.max_seq + ROW_NUMBER() OVER (PARTITION BY p.account_id ORDER BY p.%s) AS new_seq
    FROM %s p
    JOIN max_seq m ON p.account_id = m.account_id
    WHERE p.account_seq_id IS NULL OR p.account_seq_id = 0
)
UPDATE %s SET account_seq_id = ranked.new_seq
FROM ranked
WHERE %s.id = ranked.id
`, table, orderCol, table, table, table)
	case "mysql":
		sql = fmt.Sprintf(`
UPDATE %s p
JOIN (
    SELECT account_id, COALESCE(MAX(account_seq_id), 0) AS max_seq
    FROM %s
    GROUP BY account_id
) m ON p.account_id = m.account_id
JOIN (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY account_id ORDER BY %s) AS rn
    FROM %s
    WHERE account_seq_id IS NULL OR account_seq_id = 0
) r ON p.id = r.id
SET p.account_seq_id = m.max_seq + r.rn
`, table, table, orderCol, table)
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}
	return db.Exec(sql).Error
}

func seedCountersSQL(db *gorm.DB, table string, entity types.AccountSeqEntity) error {
	dialect := db.Dialector.Name()
	var sql string
	switch dialect {
	case "postgres":
		sql = fmt.Sprintf(`
INSERT INTO account_seq_counters (account_id, entity, next_id)
SELECT account_id, ?, MAX(account_seq_id) + 1
FROM %s
WHERE account_seq_id IS NOT NULL AND account_seq_id > 0
GROUP BY account_id
ON CONFLICT (account_id, entity) DO UPDATE
    SET next_id = GREATEST(account_seq_counters.next_id, EXCLUDED.next_id)
`, table)
	case "sqlite":
		sql = fmt.Sprintf(`
INSERT INTO account_seq_counters (account_id, entity, next_id)
SELECT account_id, ?, MAX(account_seq_id) + 1
FROM %s
WHERE account_seq_id IS NOT NULL AND account_seq_id > 0
GROUP BY account_id
ON CONFLICT (account_id, entity) DO UPDATE
    SET next_id = max(account_seq_counters.next_id, excluded.next_id)
`, table)
	case "mysql":
		sql = fmt.Sprintf(`
INSERT INTO account_seq_counters (account_id, entity, next_id)
SELECT account_id, ?, MAX(account_seq_id) + 1
FROM %s
WHERE account_seq_id IS NOT NULL AND account_seq_id > 0
GROUP BY account_id
ON DUPLICATE KEY UPDATE next_id = GREATEST(next_id, VALUES(next_id))
`, table)
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}
	return db.Exec(sql, string(entity)).Error
}
