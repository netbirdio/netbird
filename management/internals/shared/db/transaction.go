package db

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Tx is an open transaction handed to repository calls; nil means autocommit.
type Tx struct {
	db *gorm.DB
}

// RunInTx runs fn in one transaction that commits when fn returns nil and rolls
// back otherwise, bounded by the configured transaction timeout.
func (c *Conn) RunInTx(ctx context.Context, fn func(tx *Tx) error) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, c.txTimeout)
	defer cancel()

	startTime := time.Now()
	tx := c.db.WithContext(timeoutCtx).Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := c.applyStatementTimeouts(tx); err != nil {
		tx.Rollback()
		return err
	}

	err := c.withForeignKeyChecksDisabled(tx, func() error {
		return fn(&Tx{db: tx})
	})
	if err != nil {
		tx.Rollback()
		c.logIfTimedOut(ctx, timeoutCtx, err, "transaction", startTime)
		return err
	}

	if err := tx.Commit().Error; err != nil {
		c.logIfTimedOut(ctx, timeoutCtx, err, "transaction commit", startTime)
		return err
	}

	log.WithContext(ctx).Tracef("transaction took %v", time.Since(startTime))
	if c.metrics != nil {
		c.metrics.CountTransactionDuration(time.Since(startTime))
	}
	return nil
}

// Transaction runs fn on handle through gorm's Transaction, so a call on an
// open transaction becomes a savepoint, with the MySQL FK workaround applied.
func (c *Conn) Transaction(handle *gorm.DB, fn func(tx *gorm.DB) error) error {
	return handle.Transaction(func(tx *gorm.DB) error {
		return c.withForeignKeyChecksDisabled(tx, func() error {
			return fn(tx)
		})
	})
}

func (c *Conn) applyStatementTimeouts(tx *gorm.DB) error {
	if c.engine != PostgresStoreEngine {
		return nil
	}
	if err := tx.Exec("SET LOCAL statement_timeout = '1min'").Error; err != nil {
		return fmt.Errorf("failed to set statement timeout: %w", err)
	}
	if err := tx.Exec("SET LOCAL lock_timeout = '1min'").Error; err != nil {
		return fmt.Errorf("failed to set lock timeout: %w", err)
	}
	return nil
}

// withForeignKeyChecksDisabled runs fn with MySQL's FK checks off, which avoids
// deadlocks on MySQL and Aurora without needing SUPER privilege. The setting is
// session-scoped and survives a rollback, so it is turned back on whenever fn
// returns or panics; otherwise the pooled connection would keep it disabled.
func (c *Conn) withForeignKeyChecksDisabled(tx *gorm.DB, fn func() error) (err error) {
	if c.engine != MysqlStoreEngine {
		return fn()
	}
	if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
		return fmt.Errorf("failed to disable FK checks: %w", err)
	}
	defer func() {
		restoreErr := tx.Exec("SET FOREIGN_KEY_CHECKS = 1").Error
		if restoreErr == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("failed to re-enable FK checks: %w", restoreErr)
			return
		}
		log.WithContext(tx.Statement.Context).Warnf("failed to re-enable FK checks after failed transaction: %v", restoreErr)
	}()
	return fn()
}

func (c *Conn) logIfTimedOut(ctx, timeoutCtx context.Context, err error, phase string, startTime time.Time) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
		log.WithContext(ctx).Warnf("%s exceeded %s timeout after %v, stack: %s", phase, c.txTimeout, time.Since(startTime), debug.Stack())
	}
}
