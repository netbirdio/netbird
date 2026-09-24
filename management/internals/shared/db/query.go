package db

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type condition struct {
	expr string
	args []any
}

// Query describes which rows an operation touches and, for reads, how they are
// ordered, paged and locked. Conditions are SQL fragments with placeholders,
// so repositories never depend on the underlying ORM.
type Query struct {
	conditions []condition
	order      []string
	limit      int
	offset     int
	lock       LockingStrength
}

func NewQuery() *Query {
	return &Query{lock: LockingStrengthNone}
}

func (q *Query) Where(expr string, args ...any) *Query {
	q.conditions = append(q.conditions, condition{expr: expr, args: args})
	return q
}

func (q *Query) Order(expr string) *Query {
	q.order = append(q.order, expr)
	return q
}

func (q *Query) Limit(limit int) *Query {
	q.limit = limit
	return q
}

func (q *Query) Offset(offset int) *Query {
	q.offset = offset
	return q
}

func (q *Query) Lock(strength LockingStrength) *Query {
	q.lock = strength
	return q
}

func (q *Query) applyConditions(handle *gorm.DB) *gorm.DB {
	if q == nil {
		return handle
	}
	for _, c := range q.conditions {
		handle = handle.Where(c.expr, c.args...)
	}
	return handle
}

func (q *Query) applyRead(handle *gorm.DB) *gorm.DB {
	handle = q.applyConditions(handle)
	if q == nil {
		return handle
	}
	for _, expr := range q.order {
		handle = handle.Order(expr)
	}
	if q.limit > 0 {
		handle = handle.Limit(q.limit)
	}
	if q.offset > 0 {
		handle = handle.Offset(q.offset)
	}
	if q.lock != LockingStrengthNone {
		handle = handle.Clauses(clause.Locking{Strength: string(q.lock)})
	}
	return handle
}

// Table gives typed access to the rows of one model.
type Table[T any] struct {
	conn *Conn
}

func NewTable[T any](conn *Conn) *Table[T] {
	return &Table[T]{conn: conn}
}

func (t *Table[T]) Create(ctx context.Context, tx *Tx, value *T) error {
	return t.conn.DB(tx).WithContext(ctx).Create(value).Error
}

func (t *Table[T]) Find(ctx context.Context, tx *Tx, query *Query) ([]*T, error) {
	var values []*T
	err := query.applyRead(t.conn.DB(tx).WithContext(ctx)).Find(&values).Error
	return values, err
}

// Count returns the number of rows matching the query's conditions; ordering,
// paging and locking are ignored.
func (t *Table[T]) Count(ctx context.Context, tx *Tx, query *Query) (int64, error) {
	var model T
	var count int64
	err := query.applyConditions(t.conn.DB(tx).WithContext(ctx).Model(&model)).Count(&count).Error
	return count, err
}

// Delete removes the rows matching the query's conditions and returns how many
// were affected. A query without conditions is rejected.
func (t *Table[T]) Delete(ctx context.Context, tx *Tx, query *Query) (int64, error) {
	var model T
	result := query.applyConditions(t.conn.DB(tx).WithContext(ctx)).Delete(&model)
	return result.RowsAffected, result.Error
}
