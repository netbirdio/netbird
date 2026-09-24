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

	if err := c.applyTxSettings(tx); err != nil {
		tx.Rollback()
		return err
	}

	if err := fn(&Tx{db: tx}); err != nil {
		tx.Rollback()
		c.logIfTimedOut(ctx, timeoutCtx, err, "transaction", startTime)
		return err
	}

	if err := c.setForeignKeyChecks(tx, true); err != nil {
		tx.Rollback()
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
		if err := c.setForeignKeyChecks(tx, false); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return c.setForeignKeyChecks(tx, true)
	})
}

func (c *Conn) applyTxSettings(tx *gorm.DB) error {
	if c.engine == PostgresStoreEngine {
		if err := tx.Exec("SET LOCAL statement_timeout = '1min'").Error; err != nil {
			return fmt.Errorf("failed to set statement timeout: %w", err)
		}
		if err := tx.Exec("SET LOCAL lock_timeout = '1min'").Error; err != nil {
			return fmt.Errorf("failed to set lock timeout: %w", err)
		}
	}
	return c.setForeignKeyChecks(tx, false)
}

// setForeignKeyChecks toggles MySQL's session FK checks. Disabling them for the
// duration of a transaction avoids deadlocks on MySQL and Aurora and needs no
// SUPER privilege; other engines are left untouched.
func (c *Conn) setForeignKeyChecks(tx *gorm.DB, enabled bool) error {
	if c.engine != MysqlStoreEngine {
		return nil
	}
	if enabled {
		if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 1").Error; err != nil {
			return fmt.Errorf("failed to re-enable FK checks: %w", err)
		}
		return nil
	}
	if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
		return fmt.Errorf("failed to disable FK checks: %w", err)
	}
	return nil
}

func (c *Conn) logIfTimedOut(ctx, timeoutCtx context.Context, err error, phase string, startTime time.Time) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
		log.WithContext(ctx).Warnf("%s exceeded %s timeout after %v, stack: %s", phase, c.txTimeout, time.Since(startTime), debug.Stack())
	}
}
